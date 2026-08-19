const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY || "");
const { Resend } = require("resend");

const resend = new Resend(process.env.RESEND_API_KEY || "");

const app = express();
const port = process.env.PORT || 5000;

// ============================================================
// 1. CORS & Middlewares
// ============================================================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  process.env.CLIENT_URL,
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (e.g. mobile apps, curl, server-to-server)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin) || allowedOrigins.includes("*")) {
        return callback(null, true);
      }

      return callback(new Error(`CORS Error: Origin ${origin} not allowed by Access Control Policy`), false);
    },
    credentials: true,
  })
);

app.use(express.json());

// ============================================================
// 2. Firebase Admin Initialization (Base64 Service Account)
// ============================================================
let isFirebaseInitialized = false;

if (process.env.FB_SERVICE_KEY) {
  try {
    const decoded = Buffer.from(
      process.env.FB_SERVICE_KEY,
      "base64"
    ).toString("utf8");
    const serviceAccount = JSON.parse(decoded);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    isFirebaseInitialized = true;
    console.log("✅ Firebase Admin SDK initialized successfully");
  } catch (error) {
    console.error("❌ Failed to initialize Firebase Admin SDK:", error.message);
  }
} else {
  console.warn(
    "⚠️ FB_SERVICE_KEY not set in environment variables. Verify token in test mode."
  );
}

// ============================================================
// 3. Helper Functions & ObjectId Validator
// ============================================================
const isValidObjectId = (id) => {
  return ObjectId.isValid(id) && String(new ObjectId(id)) === id;
};

// ============================================================
// 4. Authentication Middleware: verifyFBToken
// ============================================================
/**
 * Verifies Firebase ID Token from Authorization Header:
 * - Requires 'Bearer <token>' format
 * - Verifies token signature, issuer, audience, and expiration via Firebase Admin SDK
 * - Sets req.decoded_email, req.decoded_uid, req.decoded_user
 * - Returns 401 if missing, malformed, or expired
 */
const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized: Missing or malformed Bearer authorization token",
    });
  }

  const token = authHeader.split(" ")[1];

  if (!isFirebaseInitialized) {
    // Development fallback if FB_SERVICE_KEY is pending configuration
    if (process.env.NODE_ENV === "development") {
      req.decoded_email = req.headers["x-test-email"] || "test@tuition.com";
      req.decoded_uid = "test-uid-12345";
      req.decoded_user = { email: req.decoded_email, uid: req.decoded_uid };
      return next();
    }
    return res.status(500).send({
      success: false,
      message: "Server configuration error: Firebase Admin is not initialized",
    });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    if (!decodedToken || !decodedToken.email) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized: Token does not contain a verified email address",
      });
    }

    req.decoded_email = decodedToken.email;
    req.decoded_uid = decodedToken.uid;
    req.decoded_user = decodedToken;
    next();
  } catch (error) {
    let errorMessage = "Unauthorized: Invalid or expired token";
    if (error.code === "auth/id-token-expired") {
      errorMessage = "Unauthorized: Token has expired. Please sign in again.";
    } else if (error.code === "auth/argument-error") {
      errorMessage = "Unauthorized: Invalid token format";
    }

    return res.status(401).send({
      success: false,
      message: errorMessage,
      error: error.message,
    });
  }
};

// Optional token middleware for public search feeds
const optionalFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next();
  }
  const token = authHeader.split(" ")[1];
  if (!isFirebaseInitialized) return next();

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.decoded_email = decodedToken.email;
    req.decoded_uid = decodedToken.uid;
    req.decoded_user = decodedToken;
  } catch (error) {
    // Continue without decoded user on optional token failure
  }
  next();
};

// ============================================================
// 5. MongoDB Native Driver Setup & Application Routes
// ============================================================
const uri =
  process.env.MONGO_URI ||
  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const dbName = process.env.DB_NAME || "tuitionManagementDB";
    const db = client.db(dbName);

    // Collections
    const usersCollection = db.collection("users");
    const tuitionsCollection = db.collection("tuitions");
    const applicationsCollection = db.collection("applications");
    const paymentsCollection = db.collection("payments");

    console.log(`✅ Connected to MongoDB Database: [${dbName}]`);

    // ============================================================
    // Role Authorization Middlewares (Strict Database Lookup)
    // ============================================================

    // 1. verifyAdmin: Verifies user exists in MongoDB and role === 'admin'
    const verifyAdmin = async (req, res, next) => {
      const requesterEmail = req.decoded_email;
      if (!requesterEmail) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Authenticated identity required",
        });
      }

      const user = await usersCollection.findOne({ email: requesterEmail });
      if (!user || user.role !== "admin") {
        return res.status(403).send({
          success: false,
          message: "Forbidden: Access is restricted to Administrators only",
        });
      }
      req.currentUser = user;
      next();
    };

    // 2. verifyStudent: Verifies user exists in MongoDB and role === 'student' (or 'admin')
    const verifyStudent = async (req, res, next) => {
      const requesterEmail = req.decoded_email;
      if (!requesterEmail) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Authenticated identity required",
        });
      }

      const user = await usersCollection.findOne({ email: requesterEmail });
      if (!user || (user.role !== "student" && user.role !== "admin")) {
        return res.status(403).send({
          success: false,
          message: "Forbidden: Access is restricted to Student accounts",
        });
      }
      req.currentUser = user;
      next();
    };

    // 3. verifyTutor: Verifies user exists in MongoDB and role === 'tutor' (or 'admin')
    const verifyTutor = async (req, res, next) => {
      const requesterEmail = req.decoded_email;
      if (!requesterEmail) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Authenticated identity required",
        });
      }

      const user = await usersCollection.findOne({ email: requesterEmail });
      if (!user || (user.role !== "tutor" && user.role !== "admin")) {
        return res.status(403).send({
          success: false,
          message: "Forbidden: Access is restricted to Tutor accounts",
        });
      }
      req.currentUser = user;
      next();
    };

    // ============================================================
    // 6. PUBLIC ENDPOINTS (No Authentication Required)
    // ============================================================

    // GET / - Public API greeting
    app.get("/", (req, res) => {
      res.status(200).send({
        success: true,
        message: "Tuition Management System API is running smoothly",
        version: "1.0.0",
        timestamp: new Date().toISOString(),
      });
    });

    // GET /health - Public server & database health report
    app.get("/health", async (req, res) => {
      let dbStatus = "disconnected";
      try {
        await client.db("admin").command({ ping: 1 });
        dbStatus = "connected";
      } catch (err) {
        dbStatus = `error: ${err.message}`;
      }

      res.status(200).send({
        status: "ok",
        uptime: process.uptime(),
        services: {
          database: dbStatus,
          firebaseAdmin: isFirebaseInitialized ? "initialized" : "uninitialized",
          stripeConfigured: Boolean(process.env.STRIPE_SECRET_KEY),
          resendConfigured: Boolean(process.env.RESEND_API_KEY),
        },
      });
    });

    // GET /tuitions/:id - Public Single Tuition Details
    app.get("/tuitions/:id", async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({
            success: false,
            message: "Invalid tuition ID format",
          });
        }

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        if (!tuition) {
          return res.status(404).send({
            success: false,
            message: "Tuition post not found",
          });
        }

        res.status(200).send({ success: true, tuition });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /tuitions - Public / Hybrid Browse Approved Tuitions with Search & Filters
    app.get("/tuitions", optionalFBToken, async (req, res) => {
      try {
        const {
          status,
          studentEmail,
          subject,
          class: studentClass,
          location,
          minBudget,
          maxBudget,
          search,
          page = 1,
          limit = 12,
          sort = "newest",
        } = req.query;

        const query = {};
        const requesterEmail = req.decoded_email;
        let isAdmin = false;

        if (requesterEmail) {
          const user = await usersCollection.findOne({ email: requesterEmail });
          isAdmin = user?.role === "admin";
        }

        // Authorization filter logic:
        if (studentEmail) {
          // If viewing specific student tuitions, only that student or admin can view non-approved statuses
          if (requesterEmail === studentEmail || isAdmin) {
            query.studentEmail = studentEmail;
            if (status) query.status = status;
          } else {
            query.studentEmail = studentEmail;
            query.status = "approved";
          }
        } else if (!isAdmin) {
          // Public & tutor feeds only serve 'approved' tuitions
          query.status = status || "approved";
        } else if (status) {
          query.status = status;
        }

        if (subject) {
          query.subject = { $regex: subject, $options: "i" };
        }

        if (studentClass) {
          query.class = { $regex: studentClass, $options: "i" };
        }

        if (location) {
          query.location = { $regex: location, $options: "i" };
        }

        if (minBudget || maxBudget) {
          query.budget = {};
          if (minBudget) query.budget.$gte = Number(minBudget);
          if (maxBudget) query.budget.$lte = Number(maxBudget);
        }

        if (search) {
          query.$or = [
            { subject: { $regex: search, $options: "i" } },
            { class: { $regex: search, $options: "i" } },
            { location: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
          ];
        }

        let sortOption = { createdAt: -1 };
        if (sort === "salary_asc" || sort === "budget_asc") {
          sortOption = { budget: 1 };
        } else if (sort === "salary_desc" || sort === "budget_desc") {
          sortOption = { budget: -1 };
        } else if (sort === "oldest") {
          sortOption = { createdAt: 1 };
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await tuitionsCollection.countDocuments(query);
        const tuitions = await tuitionsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.status(200).send({
          success: true,
          data: tuitions,
          tuitions,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // 7. PROTECTED ENDPOINTS: USERS & PROFILE MANAGEMENT
    // ============================================================

    // POST /users - Create or Sync User on Login/Registration (Protected: verifyFBToken)
    app.post("/users", verifyFBToken, async (req, res) => {
      try {
        const { name, photoURL, phone, role } = req.body;
        const email = req.decoded_email; // Enforce token email

        if (!email) {
          return res.status(400).send({ success: false, message: "Email is required" });
        }

        const existingUser = await usersCollection.findOne({ email });

        if (existingUser) {
          const updateDoc = {
            $set: {
              name: name || existingUser.name,
              photoURL: photoURL || existingUser.photoURL,
              phone: phone || existingUser.phone,
              updatedAt: new Date(),
            },
          };
          await usersCollection.updateOne({ email }, updateDoc);
          const updatedUser = await usersCollection.findOne({ email });
          return res.status(200).send({
            success: true,
            message: "User profile updated",
            user: updatedUser,
          });
        }

        // Assign valid role (default: student, prevent self-assigning admin)
        const assignedRole =
          role === "tutor" || role === "student" ? role : "student";

        const newUser = {
          name: name || "Anonymous User",
          email,
          photoURL: photoURL || "",
          phone: phone || "",
          role: assignedRole,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({
          success: true,
          message: "User registered successfully",
          user: { _id: result.insertedId, ...newUser },
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /users/:email/role - Check User Role (Protected: verifyFBToken)
    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      try {
        const targetEmail = req.params.email;
        const requesterEmail = req.decoded_email;

        // User can check own role, or admin can inspect any user's role
        const requester = await usersCollection.findOne({ email: requesterEmail });
        if (requesterEmail !== targetEmail && requester?.role !== "admin") {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You are only authorized to check your own role",
          });
        }

        const user = await usersCollection.findOne({ email: targetEmail });
        if (!user) {
          return res.status(404).send({ success: false, message: "User not found" });
        }

        res.status(200).send({
          success: true,
          email: user.email,
          role: user.role,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // PATCH /users/:id - Update User Profile Info (Protected: verifyFBToken + Resource Owner/Admin)
    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid user ID format" });
        }

        const userToUpdate = await usersCollection.findOne({ _id: new ObjectId(id) });
        if (!userToUpdate) {
          return res.status(404).send({ success: false, message: "User not found" });
        }

        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });

        if (userToUpdate.email !== requesterEmail && requester?.role !== "admin") {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You can only update your own profile",
          });
        }

        const { name, photoURL, phone } = req.body;
        const updateFields = { updatedAt: new Date() };
        if (name !== undefined) updateFields.name = name;
        if (photoURL !== undefined) updateFields.photoURL = photoURL;
        if (phone !== undefined) updateFields.phone = phone;

        await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields }
        );

        const updated = await usersCollection.findOne({ _id: new ObjectId(id) });
        res.status(200).send({
          success: true,
          message: "Profile updated successfully",
          user: updated,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // 8. ADMIN MANAGEMENT, REPORTS & ANALYTICS
    // ============================================================

    // GET /admin/stats - Comprehensive Platform Analytics & Metrics
    app.get("/admin/stats", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        // User statistics
        const totalUsers = await usersCollection.countDocuments();
        const totalStudents = await usersCollection.countDocuments({ role: "student" });
        const totalTutors = await usersCollection.countDocuments({ role: "tutor" });
        const totalAdmins = await usersCollection.countDocuments({ role: "admin" });

        // Tuition statistics
        const totalTuitions = await tuitionsCollection.countDocuments();
        const pendingTuitions = await tuitionsCollection.countDocuments({ status: "pending" });
        const approvedTuitions = await tuitionsCollection.countDocuments({ status: "approved" });
        const assignedTuitions = await tuitionsCollection.countDocuments({ status: "assigned" });
        const rejectedTuitions = await tuitionsCollection.countDocuments({ status: "rejected" });
        const completedTuitions = await tuitionsCollection.countDocuments({ status: "completed" });

        // Application statistics
        const totalApplications = await applicationsCollection.countDocuments();
        const pendingApplications = await applicationsCollection.countDocuments({ status: "pending" });
        const approvedApplications = await applicationsCollection.countDocuments({ status: "approved" });
        const rejectedApplications = await applicationsCollection.countDocuments({ status: "rejected" });

        // Payment & Revenue statistics
        const successfulPayments = await paymentsCollection
          .find({ paymentStatus: "completed" })
          .toArray();
        const totalSuccessfulPayments = successfulPayments.length;
        const totalPlatformEarnings = successfulPayments.reduce(
          (sum, p) => sum + (Number(p.amount) || 0),
          0
        );

        // Monthly trends for Recharts visual graphs
        const revenueByMonth = {};
        successfulPayments.forEach((p) => {
          const date = new Date(p.createdAt);
          const monthYear = date.toLocaleString("default", { month: "short", year: "numeric" });
          revenueByMonth[monthYear] = (revenueByMonth[monthYear] || 0) + (Number(p.amount) || 0);
        });

        // User registration breakdown over time
        const allUsers = await usersCollection.find().toArray();
        const usersByMonth = {};
        allUsers.forEach((u) => {
          const date = new Date(u.createdAt);
          const monthYear = date.toLocaleString("default", { month: "short", year: "numeric" });
          usersByMonth[monthYear] = (usersByMonth[monthYear] || 0) + 1;
        });

        res.status(200).send({
          success: true,
          stats: {
            totalUsers,
            totalStudents,
            totalTutors,
            totalAdmins,
            totalTuitions,
            pendingTuitions,
            approvedTuitions,
            assignedTuitions,
            rejectedTuitions,
            completedTuitions,
            totalApplications,
            pendingApplications,
            approvedApplications,
            rejectedApplications,
            totalSuccessfulPayments,
            totalPlatformEarnings,
          },
          charts: {
            revenueByMonth,
            usersByMonth,
            roleDistribution: [
              { name: "Students", value: totalStudents },
              { name: "Tutors", value: totalTutors },
              { name: "Admins", value: totalAdmins },
            ],
            tuitionStatusDistribution: [
              { name: "Pending", value: pendingTuitions },
              { name: "Approved", value: approvedTuitions },
              { name: "Assigned", value: assignedTuitions },
              { name: "Completed", value: completedTuitions },
              { name: "Rejected", value: rejectedTuitions },
            ],
          },
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // Helper handler for querying users list with search & pagination
    const handleAdminGetUsers = async (req, res) => {
      try {
        const { role, search, page = 1, limit = 20, sort = "newest" } = req.query;
        const query = {};

        if (role) {
          query.role = role;
        }

        if (search) {
          query.$or = [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
            { phone: { $regex: search, $options: "i" } },
          ];
        }

        let sortOption = { createdAt: -1 };
        if (sort === "oldest") sortOption = { createdAt: 1 };
        if (sort === "name_asc") sortOption = { name: 1 };
        if (sort === "name_desc") sortOption = { name: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await usersCollection.countDocuments(query);
        const users = await usersCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.status(200).send({
          success: true,
          data: users,
          users,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    };

    // GET /admin/users & GET /users - Get all users with filters & pagination (Admin only)
    app.get("/admin/users", verifyFBToken, verifyAdmin, handleAdminGetUsers);
    app.get("/users", verifyFBToken, verifyAdmin, handleAdminGetUsers);

    // Helper handler for updating user profile info (Admin)
    const handleAdminUpdateUser = async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid user ID format" });
        }

        const userToUpdate = await usersCollection.findOne({ _id: new ObjectId(id) });
        if (!userToUpdate) {
          return res.status(404).send({ success: false, message: "User not found" });
        }

        const { name, photoURL, phone, role } = req.body;
        const updateFields = { updatedAt: new Date() };
        if (name !== undefined) updateFields.name = name.trim();
        if (photoURL !== undefined) updateFields.photoURL = photoURL;
        if (phone !== undefined) updateFields.phone = phone.trim();

        if (role !== undefined) {
          const allowedRoles = ["student", "tutor", "admin"];
          if (!allowedRoles.includes(role)) {
            return res.status(400).send({
              success: false,
              message: `Invalid role. Allowed roles: ${allowedRoles.join(", ")}`,
            });
          }
          updateFields.role = role;
        }

        await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields }
        );

        const updated = await usersCollection.findOne({ _id: new ObjectId(id) });
        res.status(200).send({
          success: true,
          message: "User profile updated successfully",
          user: updated,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    };

    // PATCH /admin/users/:id - Update User Information (Admin only)
    app.patch("/admin/users/:id", verifyFBToken, verifyAdmin, handleAdminUpdateUser);

    // Helper handler for changing user role
    const handleAdminUpdateRole = async (req, res) => {
      try {
        const { id } = req.params;
        const { role } = req.body;

        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid user ID format" });
        }

        const allowedRoles = ["student", "tutor", "admin"];
        if (!role || !allowedRoles.includes(role)) {
          return res.status(400).send({
            success: false,
            message: `Invalid role. Allowed roles: ${allowedRoles.join(", ")}`,
          });
        }

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ success: false, message: "User not found" });
        }

        const updatedUser = await usersCollection.findOne({ _id: new ObjectId(id) });

        res.status(200).send({
          success: true,
          message: `User role successfully updated to '${role}'`,
          user: updatedUser,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    };

    // PATCH /admin/users/:id/role & PATCH /users/:id/role - Change User Role (Admin only)
    app.patch("/admin/users/:id/role", verifyFBToken, verifyAdmin, handleAdminUpdateRole);
    app.patch("/users/:id/role", verifyFBToken, verifyAdmin, handleAdminUpdateRole);

    // Helper handler for deleting user
    const handleAdminDeleteUser = async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid user ID format" });
        }

        const userToDelete = await usersCollection.findOne({ _id: new ObjectId(id) });
        if (!userToDelete) {
          return res.status(404).send({ success: false, message: "User not found" });
        }

        if (userToDelete.email === req.decoded_email) {
          return res.status(400).send({
            success: false,
            message: "Action not permitted: Administrators cannot delete their own account",
          });
        }

        await usersCollection.deleteOne({ _id: new ObjectId(id) });
        res.status(200).send({
          success: true,
          message: "User account deleted successfully",
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    };

    // DELETE /admin/users/:id & DELETE /users/:id - Delete User Account (Admin only)
    app.delete("/admin/users/:id", verifyFBToken, verifyAdmin, handleAdminDeleteUser);
    app.delete("/users/:id", verifyFBToken, verifyAdmin, handleAdminDeleteUser);

    // GET /admin/tuitions - Admin Views All Tuition Posts (Supports status filter, search, sort, pagination)
    app.get("/admin/tuitions", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const {
          status,
          search,
          subject,
          location,
          class: studentClass,
          page = 1,
          limit = 15,
          sort = "newest",
        } = req.query;

        const query = {};

        if (status) {
          query.status = status;
        }

        if (subject) {
          query.subject = { $regex: subject, $options: "i" };
        }

        if (location) {
          query.location = { $regex: location, $options: "i" };
        }

        if (studentClass) {
          query.class = { $regex: studentClass, $options: "i" };
        }

        if (search) {
          query.$or = [
            { subject: { $regex: search, $options: "i" } },
            { studentEmail: { $regex: search, $options: "i" } },
            { location: { $regex: search, $options: "i" } },
            { class: { $regex: search, $options: "i" } },
          ];
        }

        let sortOption = { createdAt: -1 };
        if (sort === "oldest") sortOption = { createdAt: 1 };
        if (sort === "budget_asc") sortOption = { budget: 1 };
        if (sort === "budget_desc") sortOption = { budget: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await tuitionsCollection.countDocuments(query);
        const tuitions = await tuitionsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Populate student profile & application counts
        const enrichedTuitions = await Promise.all(
          tuitions.map(async (t) => {
            const student = await usersCollection.findOne(
              { email: t.studentEmail },
              { projection: { name: 1, phone: 1, photoURL: 1 } }
            );
            const totalApplicants = await applicationsCollection.countDocuments({
              tuitionId: t._id,
            });
            return {
              ...t,
              student: student || null,
              totalApplicants,
            };
          })
        );

        res.status(200).send({
          success: true,
          data: enrichedTuitions,
          tuitions: enrichedTuitions,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // PATCH /admin/tuitions/:id/status - Approve or Reject Tuition Post (Admin only)
    app.patch("/admin/tuitions/:id/status", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, feedback } = req.body;

        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid tuition ID format" });
        }

        const allowedStatuses = ["approved", "rejected", "pending", "assigned", "completed"];
        if (!status || !allowedStatuses.includes(status)) {
          return res.status(400).send({
            success: false,
            message: `Invalid status. Allowed statuses: ${allowedStatuses.join(", ")}`,
          });
        }

        const targetTuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        if (!targetTuition) {
          return res.status(404).send({ success: false, message: "Tuition post not found" });
        }

        const updateDoc = {
          $set: {
            status,
            adminFeedback: feedback || "",
            updatedAt: new Date(),
          },
        };

        await tuitionsCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);
        const updatedTuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });

        res.status(200).send({
          success: true,
          message: `Tuition post status has been set to '${status}'`,
          tuition: updatedTuition,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /admin/payments - Admin Views Platform Payment Transactions
    app.get("/admin/payments", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { search, page = 1, limit = 20 } = req.query;
        const query = {};

        if (search) {
          query.$or = [
            { transactionId: { $regex: search, $options: "i" } },
            { studentEmail: { $regex: search, $options: "i" } },
            { tutorEmail: { $regex: search, $options: "i" } },
          ];
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await paymentsCollection.countDocuments(query);
        const payments = await paymentsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Calculate aggregate platform revenue
        const allCompleted = await paymentsCollection.find({ paymentStatus: "completed" }).toArray();
        const totalRevenue = allCompleted.reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

        // Enrich payments with tuition subjects
        const enrichedPayments = await Promise.all(
          payments.map(async (payment) => {
            const tuition = payment.tuitionId
              ? await tuitionsCollection.findOne(
                  { _id: new ObjectId(payment.tuitionId) },
                  { projection: { subject: 1, class: 1, location: 1 } }
                )
              : null;
            return {
              ...payment,
              tuition: tuition || null,
            };
          })
        );

        res.status(200).send({
          success: true,
          summary: {
            totalRevenue,
            totalPayments: allCompleted.length,
          },
          data: enrichedPayments,
          payments: enrichedPayments,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // 9. STUDENT FUNCTIONALITY & WORKFLOWS
    // ============================================================

    // GET /my-tuitions - View student's own posted tuitions (Student only)
    app.get("/my-tuitions", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const studentEmail = req.decoded_email;
        const { status, page = 1, limit = 20, sort = "newest" } = req.query;

        const query = { studentEmail };
        if (status) {
          query.status = status;
        }

        let sortOption = { createdAt: -1 };
        if (sort === "oldest") sortOption = { createdAt: 1 };
        if (sort === "budget_asc") sortOption = { budget: 1 };
        if (sort === "budget_desc") sortOption = { budget: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await tuitionsCollection.countDocuments(query);
        const tuitions = await tuitionsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Also attach application count for each tuition
        const tuitionsWithCounts = await Promise.all(
          tuitions.map(async (t) => {
            const applicationCount = await applicationsCollection.countDocuments({
              tuitionId: t._id,
            });
            const pendingCount = await applicationsCollection.countDocuments({
              tuitionId: t._id,
              status: "pending",
            });
            return {
              ...t,
              applicationCount,
              pendingCount,
            };
          })
        );

        res.status(200).send({
          success: true,
          total,
          page: parseInt(page),
          totalPages: Math.ceil(total / parseInt(limit)),
          tuitions: tuitionsWithCounts,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /tuitions/:id/applications - Student views tutor applications for own tuition
    app.get(
      "/tuitions/:id/applications",
      verifyFBToken,
      verifyStudent,
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!isValidObjectId(id)) {
            return res.status(400).send({
              success: false,
              message: "Invalid tuition ID format",
            });
          }

          const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
          if (!tuition) {
            return res.status(404).send({
              success: false,
              message: "Tuition post not found",
            });
          }

          const requesterEmail = req.decoded_email;
          const requester = await usersCollection.findOne({ email: requesterEmail });
          const isAdmin = requester?.role === "admin";

          // Strict ownership check: only the student who posted or an admin
          if (tuition.studentEmail !== requesterEmail && !isAdmin) {
            return res.status(403).send({
              success: false,
              message: "Forbidden: You can only view applications for your own tuition posts",
            });
          }

          const applications = await applicationsCollection
            .find({ tuitionId: new ObjectId(id) })
            .sort({ createdAt: -1 })
            .toArray();

          // Enhance application data with tutor details if available
          const enhancedApplications = await Promise.all(
            applications.map(async (appItem) => {
              const tutorProfile = await usersCollection.findOne(
                { email: appItem.tutorEmail },
                { projection: { photoURL: 1, phone: 1, name: 1 } }
              );
              return {
                ...appItem,
                tutorProfile: tutorProfile || null,
              };
            })
          );

          res.status(200).send({
            success: true,
            tuition,
            total: applications.length,
            applications: enhancedApplications,
          });
        } catch (error) {
          res.status(500).send({ success: false, message: error.message });
        }
      }
    );

    // PATCH /applications/:id/reject - Student rejects a tutor application
    app.patch(
      "/applications/:id/reject",
      verifyFBToken,
      verifyStudent,
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!isValidObjectId(id)) {
            return res.status(400).send({
              success: false,
              message: "Invalid application ID format",
            });
          }

          const application = await applicationsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!application) {
            return res.status(404).send({
              success: false,
              message: "Application not found",
            });
          }

          const tuition = await tuitionsCollection.findOne({
            _id: new ObjectId(application.tuitionId),
          });
          if (!tuition) {
            return res.status(404).send({
              success: false,
              message: "Associated tuition post not found",
            });
          }

          const requesterEmail = req.decoded_email;
          const requester = await usersCollection.findOne({ email: requesterEmail });
          const isAdmin = requester?.role === "admin";

          // Verify student owner
          if (tuition.studentEmail !== requesterEmail && !isAdmin) {
            return res.status(403).send({
              success: false,
              message: "Forbidden: You are not authorized to reject applications for this tuition",
            });
          }

          if (application.status === "approved") {
            return res.status(400).send({
              success: false,
              message: "Cannot reject an already approved application",
            });
          }

          await applicationsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "rejected", updatedAt: new Date() } }
          );

          const updatedApp = await applicationsCollection.findOne({
            _id: new ObjectId(id),
          });

          res.status(200).send({
            success: true,
            message: "Tutor application rejected successfully",
            application: updatedApp,
          });
        } catch (error) {
          res.status(500).send({ success: false, message: error.message });
        }
      }
    );

    // POST /create-checkout-session - Student initiates Stripe Checkout to Accept Tutor
    app.post(
      "/create-checkout-session",
      verifyFBToken,
      verifyStudent,
      async (req, res) => {
        try {
          const { applicationId } = req.body;

          if (!applicationId || !isValidObjectId(applicationId)) {
            return res.status(400).send({
              success: false,
              message: "A valid applicationId is required to create a checkout session",
            });
          }

          // 1. Fetch application from DB (NEVER trust frontend price)
          const application = await applicationsCollection.findOne({
            _id: new ObjectId(applicationId),
          });
          if (!application) {
            return res.status(404).send({
              success: false,
              message: "Application not found",
            });
          }

          if (application.status === "approved") {
            return res.status(400).send({
              success: false,
              message: "This application has already been approved and paid for",
            });
          }

          if (application.status === "rejected") {
            return res.status(400).send({
              success: false,
              message: "Cannot accept a rejected application",
            });
          }

          // 2. Fetch linked tuition post from DB
          const tuition = await tuitionsCollection.findOne({
            _id: new ObjectId(application.tuitionId),
          });
          if (!tuition) {
            return res.status(404).send({
              success: false,
              message: "Associated tuition requirement not found",
            });
          }

          // 3. Verify student ownership
          const requesterEmail = req.decoded_email;
          const requester = await usersCollection.findOne({ email: requesterEmail });
          const isAdmin = requester?.role === "admin";

          if (tuition.studentEmail !== requesterEmail && !isAdmin) {
            return res.status(403).send({
              success: false,
              message: "Forbidden: You are not authorized to hire for this tuition post",
            });
          }

          if (tuition.status === "assigned" || tuition.status === "completed") {
            return res.status(400).send({
              success: false,
              message: `Tuition is already ${tuition.status}. Cannot accept another tutor.`,
            });
          }

          // 4. Calculate amount strictly from expectedSalary stored in database
          const payableAmount = Number(application.expectedSalary) || Number(tuition.budget) || 100;
          const amountInCents = Math.round(payableAmount * 100);

          if (!process.env.STRIPE_SECRET_KEY) {
            // Mock checkout session response if Stripe key is not configured yet
            return res.status(200).send({
              success: true,
              message: "Stripe key is in test mode. Simulated checkout URL generated.",
              sessionId: `mock_session_${Date.now()}`,
              url: `${process.env.CLIENT_URL || "http://localhost:5173"}/dashboard/payment-success?session_id=mock_session_${Date.now()}&application_id=${application._id}&tuition_id=${tuition._id}`,
              amount: payableAmount,
              currency: "usd",
            });
          }

          const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";

          // 5. Create Stripe Checkout Session with full metadata
          const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            mode: "payment",
            customer_email: requesterEmail,
            client_reference_id: applicationId,
            metadata: {
              tuitionId: tuition._id.toString(),
              applicationId: application._id.toString(),
              studentEmail: requesterEmail,
              tutorEmail: application.tutorEmail,
              tutorName: application.tutorName || "Tutor",
              subject: tuition.subject,
              studentClass: tuition.class,
              salary: String(payableAmount),
            },
            line_items: [
              {
                price_data: {
                  currency: "usd",
                  product_data: {
                    name: `Tuition Hire: ${tuition.subject} (${tuition.class})`,
                    description: `Hiring Tutor ${application.tutorName} (${application.tutorEmail}) for ${tuition.subject} tuition`,
                  },
                  unit_amount: amountInCents,
                },
                quantity: 1,
              },
            ],
            success_url: `${clientUrl}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${clientUrl}/dashboard/tuitions/${tuition._id}/applications?canceled=true`,
          });

          res.status(200).send({
            success: true,
            sessionId: session.id,
            url: session.url,
            amount: payableAmount,
            currency: "usd",
          });
        } catch (error) {
          console.error("Stripe session creation error:", error);
          res.status(500).send({ success: false, message: error.message });
        }
      }
    );

    // POST /verify-payment & GET /payment-success - Verify Stripe Payment and Confirm Tutor Hire
    const handlePaymentVerification = async (req, res) => {
      try {
        const sessionId = req.body.sessionId || req.query.session_id;
        const fallbackAppId = req.body.applicationId || req.query.application_id;
        const fallbackTuitionId = req.body.tuitionId || req.query.tuition_id;

        if (!sessionId) {
          return res.status(400).send({
            success: false,
            message: "Missing Stripe session_id parameter",
          });
        }

        let tuitionId;
        let applicationId;
        let studentEmail = req.decoded_email;
        let tutorEmail;
        let amount = 0;
        let transactionId = sessionId;

        // Handle simulated/mock session in test environments
        if (sessionId.startsWith("mock_session_") && fallbackAppId && fallbackTuitionId) {
          tuitionId = fallbackTuitionId;
          applicationId = fallbackAppId;
          const targetApp = await applicationsCollection.findOne({
            _id: new ObjectId(applicationId),
          });
          tutorEmail = targetApp?.tutorEmail;
          amount = targetApp?.expectedSalary || 100;
        } else if (process.env.STRIPE_SECRET_KEY) {
          // Retrieve session directly from Stripe API
          const session = await stripe.checkout.sessions.retrieve(sessionId);

          if (!session) {
            return res.status(404).send({
              success: false,
              message: "Stripe checkout session not found",
            });
          }

          if (session.payment_status !== "paid") {
            return res.status(400).send({
              success: false,
              message: `Payment not completed. Status is '${session.payment_status}'`,
            });
          }

          tuitionId = session.metadata.tuitionId;
          applicationId = session.metadata.applicationId;
          studentEmail = session.metadata.studentEmail;
          tutorEmail = session.metadata.tutorEmail;
          amount = (session.amount_total || 0) / 100;
          transactionId = session.payment_intent || session.id;
        } else {
          return res.status(400).send({
            success: false,
            message: "Stripe configuration missing and invalid session identifier",
          });
        }

        if (!isValidObjectId(tuitionId) || !isValidObjectId(applicationId)) {
          return res.status(400).send({
            success: false,
            message: "Invalid tuition or application identifier in payment metadata",
          });
        }

        // Check if payment was already recorded
        const existingPayment = await paymentsCollection.findOne({
          $or: [
            { transactionId },
            { stripeSessionId: sessionId },
            { applicationId: new ObjectId(applicationId), paymentStatus: "completed" },
          ],
        });

        if (existingPayment) {
          return res.status(200).send({
            success: true,
            message: "Payment was already verified and processed",
            payment: existingPayment,
            tuitionId,
            applicationId,
          });
        }

        // 1. Record payment in MongoDB
        const paymentRecord = {
          tuitionId: new ObjectId(tuitionId),
          applicationId: new ObjectId(applicationId),
          studentEmail,
          tutorEmail,
          amount: Number(amount),
          transactionId,
          stripeSessionId: sessionId,
          paymentStatus: "completed",
          createdAt: new Date(),
        };

        const paymentResult = await paymentsCollection.insertOne(paymentRecord);

        // 2. Set application status to 'approved'
        await applicationsCollection.updateOne(
          { _id: new ObjectId(applicationId) },
          { $set: { status: "approved", paymentId: paymentResult.insertedId, updatedAt: new Date() } }
        );

        // 3. Set tuition status to 'assigned'
        await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          {
            $set: {
              status: "assigned",
              assignedTutorEmail: tutorEmail,
              hiredApplicationId: new ObjectId(applicationId),
              updatedAt: new Date(),
            },
          }
        );

        // 4. Automatically reject all other pending applications for this tuition
        const rejectResult = await applicationsCollection.updateMany(
          {
            tuitionId: new ObjectId(tuitionId),
            _id: { $ne: new ObjectId(applicationId) },
            status: "pending",
          },
          {
            $set: {
              status: "rejected",
              rejectionReason: "Another tutor was selected and hired for this tuition post",
              updatedAt: new Date(),
            },
          }
        );

        // 5. Send email notification if Resend is configured
        if (process.env.RESEND_API_KEY) {
          try {
            await resend.emails.send({
              from: "Tuition Management <onboarding@resend.dev>",
              to: [studentEmail, tutorEmail].filter(Boolean),
              subject: "🎉 Tutor Hired & Payment Confirmed - Tuition Management System",
              html: `
                <div style="font-family: sans-serif; padding: 20px; color: #333;">
                  <h2 style="color: #2563eb;">Payment & Tutor Hire Confirmed!</h2>
                  <p>A tuition requirement has been successfully assigned.</p>
                  <ul>
                    <li><strong>Amount Paid:</strong> $${amount}</li>
                    <li><strong>Transaction ID:</strong> ${transactionId}</li>
                    <li><strong>Student Email:</strong> ${studentEmail}</li>
                    <li><strong>Tutor Email:</strong> ${tutorEmail}</li>
                  </ul>
                  <p>Thank you for using the Tuition Management System.</p>
                </div>
              `,
            });
            console.log("✅ Confirmation email dispatched via Resend");
          } catch (mailErr) {
            console.warn("⚠️ Failed to send Resend confirmation email:", mailErr.message);
          }
        }

        res.status(200).send({
          success: true,
          message: "Payment successfully verified! Tutor approved and tuition assigned.",
          payment: { _id: paymentResult.insertedId, ...paymentRecord },
          tuitionId,
          applicationId,
          otherApplicationsRejected: rejectResult.modifiedCount,
        });
      } catch (error) {
        console.error("Payment verification error:", error);
        res.status(500).send({ success: false, message: error.message });
      }
    };

    app.post("/verify-payment", verifyFBToken, handlePaymentVerification);
    app.get("/payment-success", verifyFBToken, handlePaymentVerification);

    // POST /tuitions - Create a new tuition requirement (Student only)
    app.post("/tuitions", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const {
          subject,
          class: studentClass,
          location,
          budget,
          schedule,
          description,
        } = req.body;

        if (!subject || !studentClass || !location || !budget) {
          return res.status(400).send({
            success: false,
            message: "Missing required fields: subject, class, location, budget",
          });
        }

        const newTuition = {
          studentEmail: req.decoded_email, // Locked to authenticated email
          subject: subject.trim(),
          class: studentClass,
          location: location.trim(),
          budget: Number(budget),
          schedule: schedule || "3 days/week",
          description: description || "",
          status: "pending", // Always pending initially
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await tuitionsCollection.insertOne(newTuition);
        res.status(201).send({
          success: true,
          message: "Tuition post submitted successfully. Awaiting admin approval.",
          tuition: { _id: result.insertedId, ...newTuition },
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // PATCH /tuitions/:id - Update Tuition Details or Status (Student Owner or Admin)
    app.patch("/tuitions/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid tuition ID format" });
        }

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        if (!tuition) {
          return res.status(404).send({ success: false, message: "Tuition post not found" });
        }

        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });
        const isAdmin = requester?.role === "admin";
        const isOwner = tuition.studentEmail === requesterEmail;

        if (!isAdmin && !isOwner) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You are not authorized to update this tuition post",
          });
        }

        const updateFields = { updatedAt: new Date() };
        const {
          subject,
          class: studentClass,
          location,
          budget,
          schedule,
          description,
          status,
        } = req.body;

        // Admin can approve, reject, or assign status
        if (isAdmin && status) {
          const allowedStatuses = [
            "pending",
            "approved",
            "rejected",
            "assigned",
            "completed",
          ];
          if (!allowedStatuses.includes(status)) {
            return res.status(400).send({
              success: false,
              message: `Invalid status. Allowed: ${allowedStatuses.join(", ")}`,
            });
          }
          updateFields.status = status;
        }

        // Student owner can edit details if not yet assigned or completed
        if (isOwner) {
          if (tuition.status === "assigned" || tuition.status === "completed") {
            return res.status(400).send({
              success: false,
              message: "Cannot modify a tuition that is already assigned or completed",
            });
          }
          if (subject !== undefined) updateFields.subject = subject.trim();
          if (studentClass !== undefined) updateFields.class = studentClass;
          if (location !== undefined) updateFields.location = location.trim();
          if (budget !== undefined) updateFields.budget = Number(budget);
          if (schedule !== undefined) updateFields.schedule = schedule;
          if (description !== undefined) updateFields.description = description;

          // Revert to pending review on student modification
          if (!isAdmin) {
            updateFields.status = "pending";
          }
        }

        await tuitionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields }
        );

        const updatedTuition = await tuitionsCollection.findOne({
          _id: new ObjectId(id),
        });

        res.status(200).send({
          success: true,
          message: "Tuition post updated successfully",
          tuition: updatedTuition,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // DELETE /tuitions/:id - Delete Tuition Post (Student Owner or Admin)
    app.delete("/tuitions/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid tuition ID format" });
        }

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        if (!tuition) {
          return res.status(404).send({ success: false, message: "Tuition post not found" });
        }

        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });
        const isAdmin = requester?.role === "admin";
        const isOwner = tuition.studentEmail === requesterEmail;

        if (!isAdmin && !isOwner) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You are not authorized to delete this tuition post",
          });
        }

        await applicationsCollection.deleteMany({ tuitionId: new ObjectId(id) });
        await tuitionsCollection.deleteOne({ _id: new ObjectId(id) });

        res.status(200).send({
          success: true,
          message: "Tuition post and related applications deleted successfully",
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // 10. TUTOR FUNCTIONALITY & WORKFLOWS
    // ============================================================

    // POST /applications - Tutor applies for an approved tuition (Tutor only)
    app.post("/applications", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const {
          tuitionId,
          qualifications,
          experience,
          expectedSalary,
        } = req.body;

        if (!tuitionId || !qualifications || !experience || !expectedSalary) {
          return res.status(400).send({
            success: false,
            message:
              "Missing required fields: tuitionId, qualifications, experience, expectedSalary",
          });
        }

        if (!isValidObjectId(tuitionId)) {
          return res.status(400).send({ success: false, message: "Invalid tuitionId format" });
        }

        const targetTuition = await tuitionsCollection.findOne({
          _id: new ObjectId(tuitionId),
        });

        if (!targetTuition) {
          return res.status(404).send({
            success: false,
            message: "Target tuition post not found",
          });
        }

        if (targetTuition.status !== "approved") {
          return res.status(400).send({
            success: false,
            message: `Cannot apply to a tuition with status '${targetTuition.status}'. Only 'approved' tuitions can receive applications.`,
          });
        }

        // Fetch tutor identity strictly from verified token & user document
        const tutorEmail = req.decoded_email;
        const tutorUser = await usersCollection.findOne({ email: tutorEmail });
        const tutorName = tutorUser?.name || req.body.tutorName || "Tutor";

        // Prevent tutor from applying to their own posted tuition
        if (targetTuition.studentEmail === tutorEmail) {
          return res.status(400).send({
            success: false,
            message: "You cannot apply to your own tuition requirement",
          });
        }

        // Prevent duplicate application to the same tuition
        const existingApplication = await applicationsCollection.findOne({
          tuitionId: new ObjectId(tuitionId),
          tutorEmail,
        });

        if (existingApplication) {
          return res.status(409).send({
            success: false,
            message: "You have already submitted an application for this tuition post",
          });
        }

        const newApplication = {
          tuitionId: new ObjectId(tuitionId),
          tutorEmail,
          tutorName,
          qualifications: qualifications.trim(),
          experience: experience.trim(),
          expectedSalary: Number(expectedSalary),
          status: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await applicationsCollection.insertOne(newApplication);
        res.status(201).send({
          success: true,
          message: "Application submitted successfully",
          application: { _id: result.insertedId, ...newApplication },
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /my-applications - Tutor views all submitted applications with tuition details
    app.get("/my-applications", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const tutorEmail = req.decoded_email;
        const { status, page = 1, limit = 10, sort = "newest" } = req.query;

        const query = { tutorEmail };
        if (status) {
          query.status = status;
        }

        let sortOption = { createdAt: -1 };
        if (sort === "oldest") sortOption = { createdAt: 1 };
        if (sort === "salary_asc") sortOption = { expectedSalary: 1 };
        if (sort === "salary_desc") sortOption = { expectedSalary: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await applicationsCollection.countDocuments(query);
        const applications = await applicationsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Populate linked tuition details for each application
        const enhancedApplications = await Promise.all(
          applications.map(async (appItem) => {
            const tuition = await tuitionsCollection.findOne(
              { _id: new ObjectId(appItem.tuitionId) },
              {
                projection: {
                  subject: 1,
                  class: 1,
                  location: 1,
                  budget: 1,
                  schedule: 1,
                  studentEmail: 1,
                  status: 1,
                },
              }
            );

            const student = tuition?.studentEmail
              ? await usersCollection.findOne(
                  { email: tuition.studentEmail },
                  { projection: { name: 1, photoURL: 1, phone: 1 } }
                )
              : null;

            return {
              ...appItem,
              tuition: tuition || null,
              student: student || null,
            };
          })
        );

        res.status(200).send({
          success: true,
          data: enhancedApplications,
          applications: enhancedApplications,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /my-ongoing-tuitions - Tutor views approved & ongoing tuition assignments
    app.get("/my-ongoing-tuitions", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const tutorEmail = req.decoded_email;
        const { page = 1, limit = 10 } = req.query;

        const query = {
          assignedTutorEmail: tutorEmail,
          status: { $in: ["assigned", "completed"] },
        };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await tuitionsCollection.countDocuments(query);
        const ongoingTuitions = await tuitionsCollection
          .find(query)
          .sort({ updatedAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Populate student profile and payment record
        const enrichedTuitions = await Promise.all(
          ongoingTuitions.map(async (tuition) => {
            const student = await usersCollection.findOne(
              { email: tuition.studentEmail },
              { projection: { name: 1, email: 1, photoURL: 1, phone: 1 } }
            );

            const payment = await paymentsCollection.findOne({
              tuitionId: tuition._id,
              tutorEmail,
            });

            return {
              ...tuition,
              student: student || null,
              payment: payment || null,
            };
          })
        );

        res.status(200).send({
          success: true,
          data: enrichedTuitions,
          tuitions: enrichedTuitions,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /my-earnings - Tutor views revenue summary and payment history
    app.get("/my-earnings", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const tutorEmail = req.decoded_email;
        const { page = 1, limit = 10 } = req.query;

        const query = { tutorEmail, paymentStatus: "completed" };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await paymentsCollection.countDocuments(query);
        const payments = await paymentsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Aggregate summary metrics across all completed payments
        const allPayments = await paymentsCollection.find(query).toArray();
        const totalEarnings = allPayments.reduce(
          (acc, curr) => acc + (Number(curr.amount) || 0),
          0
        );

        const assignedTuitionsCount = await tuitionsCollection.countDocuments({
          assignedTutorEmail: tutorEmail,
        });

        // Monthly breakdown calculation
        const monthlyStats = {};
        allPayments.forEach((p) => {
          const date = new Date(p.createdAt);
          const monthYear = date.toLocaleString("default", { month: "short", year: "numeric" });
          monthlyStats[monthYear] = (monthlyStats[monthYear] || 0) + (Number(p.amount) || 0);
        });

        // Enhance payment items with tuition title
        const enhancedPayments = await Promise.all(
          payments.map(async (payment) => {
            const tuition = payment.tuitionId
              ? await tuitionsCollection.findOne(
                  { _id: new ObjectId(payment.tuitionId) },
                  { projection: { subject: 1, class: 1, location: 1 } }
                )
              : null;
            return {
              ...payment,
              tuition: tuition || null,
            };
          })
        );

        res.status(200).send({
          success: true,
          summary: {
            totalEarnings,
            totalPaymentsCount: allPayments.length,
            assignedTuitionsCount,
            monthlyBreakdown: monthlyStats,
          },
          data: enhancedPayments,
          payments: enhancedPayments,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /applications - Role-Aware Application List (Protected: verifyFBToken)
    app.get("/applications", verifyFBToken, async (req, res) => {
      try {
        const { tuitionId, tutorEmail, status, page = 1, limit = 20 } = req.query;
        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });
        const isAdmin = requester?.role === "admin";

        const query = {};

        if (tuitionId) {
          if (!isValidObjectId(tuitionId)) {
            return res.status(400).send({ success: false, message: "Invalid tuitionId format" });
          }
          const tuition = await tuitionsCollection.findOne({
            _id: new ObjectId(tuitionId),
          });
          if (!tuition) {
            return res.status(404).send({ success: false, message: "Tuition not found" });
          }

          // Student owner of the tuition or Admin only
          if (tuition.studentEmail !== requesterEmail && !isAdmin) {
            return res.status(403).send({
              success: false,
              message: "Forbidden: You can only view applications for your own tuition posts",
            });
          }
          query.tuitionId = new ObjectId(tuitionId);
        } else if (tutorEmail) {
          if (tutorEmail !== requesterEmail && !isAdmin) {
            return res.status(403).send({
              success: false,
              message: "Forbidden: You can only view your own applications",
            });
          }
          query.tutorEmail = tutorEmail;
        } else if (!isAdmin) {
          query.tutorEmail = requesterEmail;
        }

        if (status) {
          query.status = status;
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await applicationsCollection.countDocuments(query);
        const applications = await applicationsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.status(200).send({
          success: true,
          data: applications,
          applications,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /applications/:id - View Single Application (Applicant, Student Owner, or Admin)
    app.get("/applications/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid application ID format" });
        }

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!application) {
          return res.status(404).send({
            success: false,
            message: "Application not found",
          });
        }

        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(application.tuitionId),
        });

        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });
        const isAdmin = requester?.role === "admin";
        const isApplicant = application.tutorEmail === requesterEmail;
        const isTuitionOwner = tuition && tuition.studentEmail === requesterEmail;

        if (!isAdmin && !isApplicant && !isTuitionOwner) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You are not authorized to view this application",
          });
        }

        res.status(200).send({ success: true, application, tuition });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // PATCH /applications/:id - Update Application (Tutor edits pending / Student Owner or Admin updates status)
    app.patch("/applications/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid application ID format" });
        }

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!application) {
          return res.status(404).send({
            success: false,
            message: "Application not found",
          });
        }

        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(application.tuitionId),
        });

        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });
        const isAdmin = requester?.role === "admin";
        const isApplicant = application.tutorEmail === requesterEmail;
        const isTuitionOwner = tuition && tuition.studentEmail === requesterEmail;

        if (!isAdmin && !isApplicant && !isTuitionOwner) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You are not authorized to modify this application",
          });
        }

        const { qualifications, experience, expectedSalary, status } = req.body;
        const updateFields = { updatedAt: new Date() };

        // 1. Status Update: Student Tuition Owner or Admin
        if (status) {
          if (!isTuitionOwner && !isAdmin) {
            return res.status(403).send({
              success: false,
              message: "Forbidden: Only the student tuition owner or an admin can change application status",
            });
          }
          const allowedStatuses = ["pending", "approved", "rejected"];
          if (!allowedStatuses.includes(status)) {
            return res.status(400).send({
              success: false,
              message: `Invalid status. Allowed: ${allowedStatuses.join(", ")}`,
            });
          }
          updateFields.status = status;

          // If Student approves application, update tuition status to 'assigned'
          if (status === "approved" && tuition) {
            await tuitionsCollection.updateOne(
              { _id: tuition._id },
              { $set: { status: "assigned", updatedAt: new Date() } }
            );
          }
        }

        // 2. Content Update: Tutor applicant while pending
        if (isApplicant) {
          if (application.status !== "pending") {
            return res.status(400).send({
              success: false,
              message: "Cannot edit application after it has been reviewed or processed",
            });
          }
          if (qualifications !== undefined) updateFields.qualifications = qualifications.trim();
          if (experience !== undefined) updateFields.experience = experience.trim();
          if (expectedSalary !== undefined) updateFields.expectedSalary = Number(expectedSalary);
        }

        await applicationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields }
        );

        const updatedApplication = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });

        res.status(200).send({
          success: true,
          message: "Application updated successfully",
          application: updatedApplication,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // DELETE /applications/:id - Withdraw Application (Tutor or Admin)
    app.delete("/applications/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid application ID format" });
        }

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!application) {
          return res.status(404).send({
            success: false,
            message: "Application not found",
          });
        }

        const requesterEmail = req.decoded_email;
        const requester = await usersCollection.findOne({ email: requesterEmail });
        const isAdmin = requester?.role === "admin";
        const isApplicant = application.tutorEmail === requesterEmail;

        if (!isAdmin && !isApplicant) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: You can only withdraw your own applications",
          });
        }

        if (isApplicant && application.status !== "pending" && !isAdmin) {
          return res.status(400).send({
            success: false,
            message: "Cannot withdraw an application that has already been approved or processed",
          });
        }

        await applicationsCollection.deleteOne({ _id: new ObjectId(id) });
        res.status(200).send({
          success: true,
          message: "Application withdrawn/deleted successfully",
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // 11. PROTECTED ENDPOINTS: PAYMENTS
    // ============================================================
    app.post("/payments", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const { tuitionId, applicationId, tutorEmail, amount, transactionId } = req.body;
        if (!tuitionId || !amount || !transactionId) {
          return res.status(400).send({
            success: false,
            message: "Missing payment details: tuitionId, amount, transactionId",
          });
        }

        const newPayment = {
          tuitionId: isValidObjectId(tuitionId) ? new ObjectId(tuitionId) : tuitionId,
          applicationId: applicationId && isValidObjectId(applicationId) ? new ObjectId(applicationId) : applicationId,
          studentEmail: req.decoded_email, // Enforce authenticated student email
          tutorEmail: tutorEmail || "",
          amount: Number(amount),
          transactionId,
          paymentStatus: "completed",
          createdAt: new Date(),
        };

        const result = await paymentsCollection.insertOne(newPayment);
        res.status(201).send({
          success: true,
          message: "Payment record saved successfully",
          payment: { _id: result.insertedId, ...newPayment },
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
  }
}

run().catch(console.dir);

// ============================================================
// 12. 404 & Global Error Handling
// ============================================================
app.use((req, res) => {
  res.status(404).send({
    success: false,
    message: `Cannot ${req.method} ${req.originalUrl} - Route not found`,
  });
});

app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err.stack);
  res.status(err.status || 500).send({
    success: false,
    message: err.message || "Internal Server Error",
  });
});

// ============================================================
// 13. Server Startup
// ============================================================
app.listen(port, () => {
  console.log(`🚀 Tuition Management Server listening on port ${port}`);
});

module.exports = {
  app,
  client,
  verifyFBToken,
  ObjectId,
};


