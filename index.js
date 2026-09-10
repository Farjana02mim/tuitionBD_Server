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
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin) || allowedOrigins.includes("*")) {
        return callback(null, true);
      }
      return callback(
        new Error(
          `CORS Error: Origin ${origin} not allowed by Access Control Policy`
        ),
        false
      );
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
    const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
      "utf8"
    );
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
// 3. Helper Functions & ObjectId Sanitizers (Prevents 500 & {$oid})
// ============================================================
const toIdString = (id) => {
  if (!id) return "";
  if (typeof id === "string") return id;
  if (typeof id === "object") {
    if (id.$oid) return String(id.$oid);
    if (typeof id.toString === "function" && id.toString() !== "[object Object]") {
      return id.toString();
    }
  }
  return String(id);
};

const isValidObjectId = (id) => {
  if (!id) return false;
  const str = toIdString(id);
  return ObjectId.isValid(str) && String(new ObjectId(str)) === str;
};

// নিরাপদ তারিখ রূপান্তর (যা কখনোই RangeError ছুড়ে সার্ভার ক্র্যাশ করাবে না)
const toSafeDateIso = (val, docId) => {
  try {
    if (!val && docId && isValidObjectId(docId)) {
      const oid = new ObjectId(toIdString(docId));
      return oid.getTimestamp().toISOString();
    }
    if (!val) return new Date().toISOString();

    let d = null;
    if (typeof val === "object") {
      if (val.$date) {
        if (typeof val.$date === "object" && val.$date.$numberLong) {
          d = new Date(Number(val.$date.$numberLong));
        } else {
          d = new Date(val.$date);
        }
      } else if (val instanceof Date) {
        d = val;
      }
    } else if (typeof val === "number") {
      d = val < 10000000000 ? new Date(val * 1000) : new Date(val);
    } else if (typeof val === "string") {
      const trimmed = val.trim();
      if (/^\d{10}$/.test(trimmed)) {
        d = new Date(Number(trimmed) * 1000);
      } else if (/^\d{13}$/.test(trimmed)) {
        d = new Date(Number(trimmed));
      } else {
        d = new Date(trimmed);
      }
    }

    // d ভ্যালিড হলেই কেবল toISOString() হবে
    if (d && !isNaN(d.getTime())) {
      return d.toISOString();
    }

    // তারিখ ইনভ্যালিড হলে _id থেকে আসল তৈরির তারিখ নেওয়া হবে
    if (docId && isValidObjectId(docId)) {
      const oid = new ObjectId(toIdString(docId));
      return oid.getTimestamp().toISOString();
    }
  } catch (err) {
    // ignore
  }
  return new Date().toISOString();
};

const sanitizePaymentDoc = (p) => {
  if (!p) return p;
  try {
    const rawDate = p.createdAt || p.date || p.paymentDate || p.paidAt || p.timestamp;
    const createdAt = toSafeDateIso(rawDate, p._id);

    return {
      ...p,
      _id: toIdString(p._id),
      tuitionId: toIdString(p.tuitionId),
      applicationId: toIdString(p.applicationId),
      paymentId: toIdString(p.paymentId),
      transactionId: toIdString(p.transactionId),
      createdAt,
    };
  } catch (err) {
    return {
      ...p,
      _id: toIdString(p?._id),
      tuitionId: toIdString(p?.tuitionId),
      createdAt: new Date().toISOString(),
    };
  }
};

const sanitizeTuitionDoc = (t) => {
  if (!t) return t;
  return {
    ...t,
    _id: toIdString(t._id),
    description: t.description || "",
  };
};

// ============================================================
// 4. Authentication Middleware: verifyFBToken
// ============================================================
const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized: Missing or malformed Bearer authorization token",
    });
  }

  const token = authHeader.split(" ")[1];

  if (isFirebaseInitialized) {
    try {
      const decodedToken = await admin.auth().verifyIdToken(token);
      if (!decodedToken || !decodedToken.email) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Token does not contain a verified email address",
        });
      }

      req.decoded_email = decodedToken.email.toLowerCase();
      req.decoded_uid = decodedToken.uid;
      req.decoded_user = decodedToken;
      return next();
    } catch (error) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized: Invalid or expired token",
        error: error.message,
      });
    }
  }

  // ডেভেলপমেন্ট ফলব্যাক (FB_SERVICE_KEY সেট না থাকলেও ক্র্যাশ করবে না)
  try {
    const payloadPart = token.split(".")[1];
    if (payloadPart) {
      const decoded = JSON.parse(
        Buffer.from(payloadPart, "base64").toString("utf8")
      );
      if (decoded && (decoded.email || decoded.user_id)) {
        req.decoded_email = (decoded.email || "test@tuition.com").toLowerCase();
        req.decoded_uid = decoded.user_id || decoded.sub || "test-uid-12345";
        req.decoded_user = decoded;
        return next();
      }
    }
  } catch (parseErr) {
    console.warn("JWT payload decode warning:", parseErr.message);
  }

  req.decoded_email = (req.headers["x-test-email"] || "test@tuition.com").toLowerCase();
  req.decoded_uid = "test-uid-12345";
  req.decoded_user = { email: req.decoded_email, uid: req.decoded_uid };
  next();
};

const optionalFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next();
  }
  const token = authHeader.split(" ")[1];
  if (!isFirebaseInitialized) return next();

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.decoded_email = decodedToken.email.toLowerCase();
    req.decoded_uid = decodedToken.uid;
    req.decoded_user = decodedToken;
  } catch (error) {
    // Continue silently
  }
  next();
};

// ============================
// MongoDB Connection
// ============================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.8v42xkx.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: ServerApiVersion.v1,
});

async function run() {
  try {
    await client.connect();

    const db = client.db("etuitionDB");

    // Collections
    const usersCollection = db.collection("users");
    const tuitionsCollection = db.collection("tuitions");
    const applicationsCollection = db.collection("applications");
    const paymentsCollection = db.collection("payments");

    console.log("✅ Connected to MongoDB.");

    // ============================================================
    // Role Authorization Middlewares (Case-Insensitive & Auto-Sync)
    // ============================================================

    // 1. verifyAdmin
    const verifyAdmin = async (req, res, next) => {
      const requesterEmail = req.decoded_email;
      if (!requesterEmail) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Authenticated identity required",
        });
      }

      const user = await usersCollection.findOne({
        email: { $regex: new RegExp(`^${requesterEmail.trim()}$`, "i") },
      });

      if (!user || user.role !== "admin") {
        return res.status(403).send({
          success: false,
          message: "Forbidden: Access is restricted to Administrators only",
        });
      }
      req.currentUser = user;
      next();
    };

    // 2. verifyStudent (Case-Insensitive & Auto-creates Student Profile if missing)
    const verifyStudent = async (req, res, next) => {
      const requesterEmail = req.decoded_email;
      if (!requesterEmail) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Authenticated identity required",
        });
      }

      let user = await usersCollection.findOne({
        email: { $regex: new RegExp(`^${requesterEmail.trim()}$`, "i") },
      });

      if (!user) {
        const newUser = {
          name: req.decoded_user?.name || "Student User",
          email: requesterEmail.toLowerCase(),
          photoURL: req.decoded_user?.picture || "",
          phone: "",
          role: "student",
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const insertRes = await usersCollection.insertOne(newUser);
        user = { _id: insertRes.insertedId, ...newUser };
      }

      if (user.role !== "student" && user.role !== "admin") {
        return res.status(403).send({
          success: false,
          message: `Forbidden: Access restricted to Student accounts. Current role: '${user.role}'`,
        });
      }
      req.currentUser = user;
      next();
    };

    // 3. verifyTutor
    const verifyTutor = async (req, res, next) => {
      const requesterEmail = req.decoded_email;
      if (!requesterEmail) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Authenticated identity required",
        });
      }

      let user = await usersCollection.findOne({
        email: { $regex: new RegExp(`^${requesterEmail.trim()}$`, "i") },
      });

      if (!user) {
        const newUser = {
          name: req.decoded_user?.name || "Tutor User",
          email: requesterEmail.toLowerCase(),
          photoURL: req.decoded_user?.picture || "",
          phone: "",
          role: "tutor",
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const insertRes = await usersCollection.insertOne(newUser);
        user = { _id: insertRes.insertedId, ...newUser };
      }

      if (user.role !== "tutor" && user.role !== "admin") {
        return res.status(403).send({
          success: false,
          message: `Forbidden: Access restricted to Tutor accounts. Current role: '${user.role}'`,
        });
      }
      req.currentUser = user;
      next();
    };

    // ============================================================
    // PUBLIC ENDPOINTS
    // ============================================================

    app.get("/", (req, res) => {
      res.status(200).send({
        success: true,
        message: "Tuition Management System API is running smoothly",
        version: "1.0.0",
      });
    });

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

    app.get("/tuitions/:id", async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid tuition ID format" });
        }

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        if (!tuition) {
          return res.status(404).send({ success: false, message: "Tuition post not found" });
        }

        const sanitized = sanitizeTuitionDoc(tuition);
        res.status(200).send({ success: true, tuition: sanitized, data: sanitized });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

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
          const user = await usersCollection.findOne({
            email: { $regex: new RegExp(`^${requesterEmail.trim()}$`, "i") },
          });
          isAdmin = user?.role === "admin";
        }

        if (studentEmail) {
          query.studentEmail = { $regex: new RegExp(`^${studentEmail.trim()}$`, "i") };
          if (status) query.status = status;
          else if (!isAdmin && requesterEmail !== studentEmail.toLowerCase()) {
            query.status = "approved";
          }
        } else if (!isAdmin) {
          query.status = status || "approved";
        } else if (status) {
          query.status = status;
        }

        if (subject) query.subject = { $regex: subject, $options: "i" };
        if (studentClass) query.class = { $regex: studentClass, $options: "i" };
        if (location) query.location = { $regex: location, $options: "i" };

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
        if (sort === "salary_asc" || sort === "budget_asc") sortOption = { budget: 1 };
        else if (sort === "salary_desc" || sort === "budget_desc") sortOption = { budget: -1 };
        else if (sort === "oldest") sortOption = { createdAt: 1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await tuitionsCollection.countDocuments(query);
        const tuitions = await tuitionsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        const sanitizedList = tuitions.map(sanitizeTuitionDoc);

        res.status(200).send({
          success: true,
          data: sanitizedList,
          tuitions: sanitizedList,
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
    // USERS & PROFILE MANAGEMENT
    // ============================================================

    app.post("/users", verifyFBToken, async (req, res) => {
      try {
        const { name, photoURL, phone, role } = req.body;
        const email = req.decoded_email;

        if (!email) {
          return res.status(400).send({ success: false, message: "Email is required" });
        }

        const existingUser = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email.trim()}$`, "i") },
        });

        if (existingUser) {
          const updateDoc = {
            $set: {
              name: name || existingUser.name,
              photoURL: photoURL !== undefined && photoURL !== "" ? photoURL : existingUser.photoURL,
              phone: phone || existingUser.phone,
              updatedAt: new Date(),
            },
          };

          if (role && (role === "tutor" || role === "student")) {
            updateDoc.$set.role = role;
          }

          await usersCollection.updateOne({ _id: existingUser._id }, updateDoc);
          const updatedUser = await usersCollection.findOne({ _id: existingUser._id });
          return res.status(200).send({
            success: true,
            message: "User profile updated",
            user: updatedUser,
          });
        }

        const assignedRole = role === "tutor" || role === "student" ? role : "student";
        const newUser = {
          name: name || "Anonymous User",
          email: email.toLowerCase(),
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

    app.patch("/user/profile", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { name, photoURL, phone } = req.body;

        const updateFields = { updatedAt: new Date() };
        if (name !== undefined) updateFields.name = name.trim();
        if (photoURL !== undefined) updateFields.photoURL = photoURL;
        if (phone !== undefined) updateFields.phone = phone.trim();

        await usersCollection.updateOne(
          { email: { $regex: new RegExp(`^${email.trim()}$`, "i") } },
          { $set: updateFields }
        );

        const updated = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email.trim()}$`, "i") },
        });

        res.status(200).send({
          success: true,
          message: "Profile updated successfully",
          user: updated,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      try {
        const targetEmail = req.params.email;
        const user = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${targetEmail.trim()}$`, "i") },
        });

        if (!user) {
          return res.status(200).send({ success: true, email: targetEmail, role: "student" });
        }

        res.status(200).send({
          success: true,
          email: user.email,
          role: user.role || "student",
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // ADMIN ENDPOINTS
    // ============================================================

    app.get("/admin/stats", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await usersCollection.countDocuments();
        const totalStudents = await usersCollection.countDocuments({ role: "student" });
        const totalTutors = await usersCollection.countDocuments({ role: "tutor" });
        const totalAdmins = await usersCollection.countDocuments({ role: "admin" });

        const totalTuitions = await tuitionsCollection.countDocuments();
        const pendingTuitions = await tuitionsCollection.countDocuments({ status: "pending" });
        const approvedTuitions = await tuitionsCollection.countDocuments({ status: "approved" });
        const assignedTuitions = await tuitionsCollection.countDocuments({ status: "assigned" });
        const rejectedTuitions = await tuitionsCollection.countDocuments({ status: "rejected" });

        const totalApplications = await applicationsCollection.countDocuments();
        const approvedApplications = await applicationsCollection.countDocuments({ status: "approved" });

        const successfulPayments = await paymentsCollection.find({ paymentStatus: "completed" }).toArray();
        const totalPayments = successfulPayments.length;
        const totalRevenue = successfulPayments.reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

        const statsData = {
          totalUsers,
          totalStudents,
          totalTutors,
          totalAdmins,
          totalTuitions,
          pendingTuitions,
          approvedTuitions,
          assignedTuitions,
          rejectedTuitions,
          totalApplications,
          approvedApplications,
          totalPayments,
          totalRevenue,
          totalSuccessfulPayments: totalPayments,
          totalPlatformEarnings: totalRevenue,
        };

        res.status(200).send({
          success: true,
          data: statsData,
          stats: statsData,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    const handleAdminGetUsers = async (req, res) => {
      try {
        const { role, search, page = 1, limit = 20, sort = "newest" } = req.query;
        const query = {};

        if (role) query.role = role;
        if (search) {
          query.$or = [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
            { phone: { $regex: search, $options: "i" } },
          ];
        }

        let sortOption = { createdAt: -1 };
        if (sort === "oldest") sortOption = { createdAt: 1 };

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

    app.get("/admin/users", verifyFBToken, verifyAdmin, handleAdminGetUsers);
    app.get("/users", verifyFBToken, verifyAdmin, handleAdminGetUsers);

    app.patch("/admin/users/:id/role", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { role } = req.body;
        if (!isValidObjectId(id)) return res.status(400).send({ success: false, message: "Invalid ID" });

        await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role, updatedAt: new Date() } }
        );
        res.status(200).send({ success: true, message: "Role updated" });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.delete("/admin/users/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ success: false, message: "Invalid ID" });
        await usersCollection.deleteOne({ _id: new ObjectId(id) });
        res.status(200).send({ success: true, message: "User deleted" });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.get("/admin/tuitions", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { status } = req.query;
        const query = status ? { status } : {};
        const tuitions = await tuitionsCollection.find(query).sort({ createdAt: -1 }).toArray();

        const sanitized = tuitions.map(sanitizeTuitionDoc);
        res.status(200).send({
          success: true,
          data: sanitized,
          tuitions: sanitized,
          total: sanitized.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.patch("/admin/tuitions/:id/status", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, rejectionReason } = req.body;
        if (!isValidObjectId(id)) return res.status(400).send({ success: false, message: "Invalid ID" });

        await tuitionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, rejectionReason: rejectionReason || "", updatedAt: new Date() } }
        );
        res.status(200).send({ success: true, message: "Status updated" });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.get("/admin/payments", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const payments = await paymentsCollection.find().sort({ createdAt: -1 }).toArray();
        const sanitized = payments.map(sanitizePaymentDoc);

        res.status(200).send({
          success: true,
          data: sanitized,
          payments: sanitized,
          total: sanitized.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // STUDENT ENDPOINTS & WORKFLOWS
    // ============================================================

    app.get("/my-tuitions", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const studentEmail = req.decoded_email;
        const query = {
          studentEmail: { $regex: new RegExp(`^${studentEmail.trim()}$`, "i") },
        };

        const tuitions = await tuitionsCollection.find(query).sort({ createdAt: -1 }).toArray();

        const tuitionsWithCounts = await Promise.all(
          tuitions.map(async (t) => {
            const applicationCount = await applicationsCollection.countDocuments({ tuitionId: t._id });
            return sanitizeTuitionDoc({ ...t, applicationCount });
          })
        );

        res.status(200).send({
          success: true,
          data: tuitionsWithCounts,
          tuitions: tuitionsWithCounts,
          total: tuitionsWithCounts.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET /my-payments - স্যানিটাইজড ও ১০০% ক্র্যাশ-প্রুফ রুট
    app.get("/my-payments", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const studentEmail = (req.decoded_email || "").trim().toLowerCase();
        if (!studentEmail) {
          return res.status(200).send({ success: true, data: [], payments: [], total: 0 });
        }

        // বিশেষ ক্যারেক্টারযুক্ত ইমেইল নিরাপদ করতে Regex Escape
        const escapedEmail = studentEmail.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const payments = await paymentsCollection
          .find({
            studentEmail: { $regex: new RegExp(`^${escapedEmail}$`, "i") },
          })
          .sort({ createdAt: -1 })
          .toArray();

        const sanitized = (payments || []).map(sanitizePaymentDoc);

        res.status(200).send({
          success: true,
          data: sanitized,
          payments: sanitized,
          total: sanitized.length,
        });
      } catch (error) {
        console.error("Error in /my-payments:", error);
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // POST /tuitions - Create Tuition (With Description Field)
    app.post("/tuitions", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const { subject, class: studentClass, location, budget, schedule, description } = req.body;

        if (!subject || !studentClass || !location || !budget) {
          return res.status(400).send({
            success: false,
            message: "Missing required fields: subject, class, location, budget",
          });
        }

        const newTuition = {
          studentEmail: req.decoded_email.toLowerCase(),
          subject: subject.trim(),
          class: studentClass,
          location: location.trim(),
          budget: Number(budget),
          schedule: (schedule || "Flexible").trim(),
          description: (description || "").trim(),
          status: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await tuitionsCollection.insertOne(newTuition);
        const createdTuition = sanitizeTuitionDoc({ _id: result.insertedId, ...newTuition });

        res.status(201).send({
          success: true,
          message: "Tuition post submitted successfully",
          tuition: createdTuition,
          data: createdTuition,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // PUT & PATCH /tuitions/:id - Student Edit Tuition
    const handleUpdateTuition = async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) {
          return res.status(400).send({ success: false, message: "Invalid tuition ID format" });
        }

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        if (!tuition) {
          return res.status(404).send({ success: false, message: "Tuition post not found" });
        }

        const requesterEmail = req.decoded_email.toLowerCase();
        const isOwner = tuition.studentEmail && tuition.studentEmail.toLowerCase() === requesterEmail;

        if (!isOwner) {
          const requester = await usersCollection.findOne({
            email: { $regex: new RegExp(`^${requesterEmail}$`, "i") },
          });
          if (requester?.role !== "admin") {
            return res.status(403).send({ success: false, message: "Forbidden" });
          }
        }

        const { subject, class: studentClass, location, budget, schedule, description } = req.body;
        const updateFields = { updatedAt: new Date() };

        if (subject !== undefined) updateFields.subject = subject.trim();
        if (studentClass !== undefined) updateFields.class = studentClass;
        if (location !== undefined) updateFields.location = location.trim();
        if (budget !== undefined) updateFields.budget = Number(budget);
        if (schedule !== undefined) updateFields.schedule = schedule;
        if (description !== undefined) updateFields.description = description.trim();

        await tuitionsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateFields });
        const updated = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        const sanitized = sanitizeTuitionDoc(updated);

        res.status(200).send({ success: true, message: "Tuition updated", data: sanitized, tuition: sanitized });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    };

    app.patch("/tuitions/:id", verifyFBToken, handleUpdateTuition);
    app.put("/tuitions/:id", verifyFBToken, handleUpdateTuition);

    app.delete("/tuitions/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ success: false, message: "Invalid ID" });

        await applicationsCollection.deleteMany({ tuitionId: new ObjectId(id) });
        await tuitionsCollection.deleteOne({ _id: new ObjectId(id) });
        res.status(200).send({ success: true, message: "Tuition deleted" });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.get("/tuitions/:id/applications", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ success: false, message: "Invalid ID" });

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
        const applications = await applicationsCollection
          .find({ tuitionId: new ObjectId(id) })
          .sort({ createdAt: -1 })
          .toArray();

        const cleanApps = applications.map((a) => ({
          ...a,
          _id: toIdString(a._id),
          tuitionId: toIdString(a.tuitionId),
        }));

        res.status(200).send({
          success: true,
          tuition: sanitizeTuitionDoc(tuition),
          applications: cleanApps,
          data: cleanApps,
          total: cleanApps.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.patch("/applications/:id/reject", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ success: false, message: "Invalid ID" });

        await applicationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "rejected", updatedAt: new Date() } }
        );
        res.status(200).send({ success: true, message: "Application rejected" });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // STRIPE CHECKOUT & PAYMENT VERIFICATION
    // ============================================================

    app.post("/create-checkout-session", verifyFBToken, verifyStudent, async (req, res) => {
      try {
        const { applicationId } = req.body;
        if (!applicationId || !isValidObjectId(applicationId)) {
          return res.status(400).send({ success: false, message: "Valid applicationId required" });
        }

        const application = await applicationsCollection.findOne({ _id: new ObjectId(applicationId) });
        if (!application) return res.status(404).send({ success: false, message: "Application not found" });

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(application.tuitionId) });
        if (!tuition) return res.status(404).send({ success: false, message: "Tuition post not found" });

        const payableAmount = Number(application.expectedSalary) || Number(tuition.budget) || 100;
        const amountInCents = Math.round(payableAmount * 100);

        if (!process.env.STRIPE_SECRET_KEY) {
          return res.status(200).send({
            success: true,
            sessionId: `mock_session_${Date.now()}`,
            url: `${process.env.CLIENT_URL || "http://localhost:5173"}/dashboard/payment-success?session_id=mock_session_${Date.now()}&application_id=${application._id}&tuition_id=${tuition._id}`,
            amount: payableAmount,
          });
        }

        const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          customer_email: req.decoded_email,
          client_reference_id: applicationId,
          metadata: {
            tuitionId: tuition._id.toString(),
            applicationId: application._id.toString(),
            studentEmail: req.decoded_email,
            tutorEmail: application.tutorEmail,
            salary: String(payableAmount),
          },
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: `Tuition Hire: ${tuition.subject} (${tuition.class})`,
                },
                unit_amount: amountInCents,
              },
              quantity: 1,
            },
          ],
          success_url: `${clientUrl}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${clientUrl}/dashboard/student/my-tuitions`,
        });

        res.status(200).send({ success: true, sessionId: session.id, url: session.url });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.post("/verify-payment", verifyFBToken, async (req, res) => {
      try {
        const { sessionId } = req.body;
        if (!sessionId) return res.status(400).send({ success: false, message: "sessionId required" });

        let tuitionId;
        let applicationId;
        let studentEmail = req.decoded_email;
        let tutorEmail;
        let amount = 0;
        let transactionId = sessionId;

        if (sessionId.startsWith("mock_session_")) {
          const appItem = await applicationsCollection.findOne();
          applicationId = appItem?._id;
          tuitionId = appItem?.tuitionId;
          tutorEmail = appItem?.tutorEmail;
          amount = appItem?.expectedSalary || 100;
        } else if (process.env.STRIPE_SECRET_KEY) {
          const session = await stripe.checkout.sessions.retrieve(sessionId);
          tuitionId = session.metadata.tuitionId;
          applicationId = session.metadata.applicationId;
          studentEmail = session.metadata.studentEmail;
          tutorEmail = session.metadata.tutorEmail;
          amount = (session.amount_total || 0) / 100;
          transactionId = session.payment_intent || session.id;
        }

        const paymentRecord = {
          tuitionId: new ObjectId(tuitionId),
          applicationId: new ObjectId(applicationId),
          studentEmail,
          tutorEmail,
          amount: Number(amount),
          transactionId: String(transactionId),
          stripeSessionId: sessionId,
          paymentStatus: "completed",
          createdAt: new Date(),
        };

        const paymentResult = await paymentsCollection.insertOne(paymentRecord);

        await applicationsCollection.updateOne(
          { _id: new ObjectId(applicationId) },
          { $set: { status: "approved", paymentId: paymentResult.insertedId, updatedAt: new Date() } }
        );

        await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          { $set: { status: "assigned", assignedTutorEmail: tutorEmail, updatedAt: new Date() } }
        );

        const cleanPayment = sanitizePaymentDoc({ _id: paymentResult.insertedId, ...paymentRecord });

        res.status(200).send({
          success: true,
          message: "Payment verified successfully",
          payment: cleanPayment,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ============================================================
    // TUTOR ENDPOINTS & WORKFLOWS
    // ============================================================

    app.post("/applications", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const { tuitionId, qualifications, experience, expectedSalary, tutorName } = req.body;
        if (!tuitionId || !qualifications || !experience || !expectedSalary) {
          return res.status(400).send({ success: false, message: "Missing required application fields" });
        }

        const newApplication = {
          tuitionId: new ObjectId(tuitionId),
          tutorEmail: req.decoded_email,
          tutorName: tutorName || "Tutor",
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
          message: "Application submitted",
          application: { _id: result.insertedId, ...newApplication },
          data: { _id: result.insertedId, ...newApplication },
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.get("/my-applications", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const tutorEmail = req.decoded_email;
        const applications = await applicationsCollection
          .find({ tutorEmail: { $regex: new RegExp(`^${tutorEmail.trim()}$`, "i") } })
          .sort({ createdAt: -1 })
          .toArray();

        const enhanced = await Promise.all(
          applications.map(async (appItem) => {
            const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(appItem.tuitionId) });
            return {
              ...appItem,
              _id: toIdString(appItem._id),
              tuitionId: toIdString(appItem.tuitionId),
              tuitionSubject: tuition?.subject,
              tuitionLocation: tuition?.location,
              tuitionBudget: tuition?.budget,
            };
          })
        );

        res.status(200).send({
          success: true,
          data: enhanced,
          applications: enhanced,
          total: enhanced.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.get("/my-ongoing-tuitions", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const tutorEmail = req.decoded_email;
        const ongoing = await tuitionsCollection
          .find({
            assignedTutorEmail: { $regex: new RegExp(`^${tutorEmail.trim()}$`, "i") },
            status: { $in: ["assigned", "completed"] },
          })
          .sort({ updatedAt: -1 })
          .toArray();

        const sanitized = ongoing.map(sanitizeTuitionDoc);

        res.status(200).send({
          success: true,
          data: sanitized,
          tuitions: sanitized,
          total: sanitized.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    const handleTutorEarnings = async (req, res) => {
      try {
        const tutorEmail = req.decoded_email;
        const payments = await paymentsCollection
          .find({
            tutorEmail: { $regex: new RegExp(`^${tutorEmail.trim()}$`, "i") },
            paymentStatus: "completed",
          })
          .sort({ createdAt: -1 })
          .toArray();

        const sanitized = payments.map(sanitizePaymentDoc);

        res.status(200).send({
          success: true,
          data: sanitized,
          payments: sanitized,
          total: sanitized.length,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    };

    app.get("/my-earnings", verifyFBToken, verifyTutor, handleTutorEarnings);
    app.get("/tutor/earnings", verifyFBToken, verifyTutor, handleTutorEarnings);

    // ============================================================
    // 404 & Global Error Handling
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
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
  }
}

run()
  .then(() => {
    app.listen(port, () => {
      console.log(`🚀 Tuition Management Server listening on port ${port}`);
    });
  })
  .catch(console.dir);

module.exports = {
  app,
  client,
  verifyFBToken,
  ObjectId,
};