require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const admin = require('firebase-admin')

const port = process.env.PORT || 5000
const app = express()

/* =========================
   Firebase Admin Setup
========================= */
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8')
const serviceAccount = JSON.parse(decoded)

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
})

/* =========================
   Middleware
========================= */
app.use(
  cors({
    origin: [process.env.CLIENT_DOMAIN],
    credentials: true,
  })
)
app.use(express.json())

/* =========================
   JWT Verify (Firebase)
========================= */
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(' ')[1]
  if (!token) return res.status(401).send({ message: 'Unauthorized' })

  try {
    const decoded = await admin.auth().verifyIdToken(token)
    req.tokenEmail = decoded.email
    next()
  } catch {
    res.status(401).send({ message: 'Unauthorized' })
  }
}

/* =========================
   MongoDB Setup
========================= */

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.8v42xkx.mongodb.net/?appName=Cluster0`
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
})

async function run() {
  try {
    const db = client.db('etuitionDB')
    const usersCollection = db.collection('users')
    const tuitionsCollection = db.collection('tuitions')
    const applicationsCollection = db.collection('applications')
    const paymentsCollection = db.collection('payments')
    const tutorRequestsCollection = db.collection('tutorRequests')

    /* =========================
       Role Middlewares
    ========================= */
    const verifyADMIN = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.tokenEmail })
      if (user?.role !== 'admin') return res.status(403).send({ message: 'Admin only' })
      next()
    }

    const verifySTUDENT = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.tokenEmail })
      if (user?.role !== 'student') return res.status(403).send({ message: 'Student only' })
      next()
    }

    const verifyTUTOR = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.tokenEmail })
      if (user?.role !== 'tutor') return res.status(403).send({ message: 'Tutor only' })
      next()
    }

    /* =========================
       USERS
    ========================= */
    app.post('/user', async (req, res) => {
      const user = req.body
      const exists = await usersCollection.findOne({ email: user.email })

      if (exists) {
        await usersCollection.updateOne(
          { email: user.email },
          { $set: { lastLogin: new Date() } }
        )
        return res.send({ message: 'User updated' })
      }

      user.role = 'student'
      user.createdAt = new Date()
      await usersCollection.insertOne(user)
      res.send({ message: 'User created' })
    })

    app.get('/user/role', verifyJWT, async (req, res) => {
      const user = await usersCollection.findOne({ email: req.tokenEmail })
      res.send({ role: user?.role })
    })

    app.get('/users', verifyJWT, verifyADMIN, async (req, res) => {
      const users = await usersCollection.find().toArray()
      res.send(users)
    })

    app.patch('/update-role', verifyJWT, verifyADMIN, async (req, res) => {
      const { email, role } = req.body
      const result = await usersCollection.updateOne({ email }, { $set: { role } })
      await tutorRequestsCollection.deleteOne({ email })
      res.send(result)
    })

    /* =========================
       TUTOR REQUEST
    ========================= */
    app.post('/become-tutor', verifyJWT, async (req, res) => {
      const exists = await tutorRequestsCollection.findOne({ email: req.tokenEmail })
      if (exists) return res.status(409).send({ message: 'Already requested' })

      const result = await tutorRequestsCollection.insertOne({
        email: req.tokenEmail,
        requestedAt: new Date(),
      })
      res.send(result)
    })

    app.get('/tutor-requests', verifyJWT, verifyADMIN, async (req, res) => {
      const requests = await tutorRequestsCollection.find().toArray()
      res.send(requests)
    })

    /* =========================
       TUITIONS
    ========================= */
    app.post('/tuitions', verifyJWT, verifySTUDENT, async (req, res) => {
      const tuition = {
        ...req.body,
        studentEmail: req.tokenEmail,
        status: 'pending',
        createdAt: new Date(),
      }
      const result = await tuitionsCollection.insertOne(tuition)
      res.send(result)
    })

    app.get('/tuitions', async (req, res) => {
      const tuitions = await tuitionsCollection.find({ status: 'approved' }).toArray()
      res.send(tuitions)
    })

    app.get('/tuitions/:id', async (req, res) => {
      const tuition = await tuitionsCollection.findOne({
        _id: new ObjectId(req.params.id),
      })
      res.send(tuition)
    })

    app.get('/my-tuitions', verifyJWT, verifySTUDENT, async (req, res) => {
      const tuitions = await tuitionsCollection
        .find({ studentEmail: req.tokenEmail })
        .toArray()
      res.send(tuitions)
    })

    app.patch('/tuitions/status/:id', verifyJWT, verifyADMIN, async (req, res) => {
      const { status } = req.body
      const result = await tuitionsCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status } }
      )
      res.send(result)
    })

    /* =========================
       APPLICATIONS
    ========================= */
    app.post('/apply', verifyJWT, verifyTUTOR, async (req, res) => {
      const { tuitionId } = req.body
      const exists = await applicationsCollection.findOne({
        tuitionId,
        tutorEmail: req.tokenEmail,
      })

      if (exists) return res.status(409).send({ message: 'Already applied' })

      const application = {
        ...req.body,
        tutorEmail: req.tokenEmail,
        status: 'pending',
        createdAt: new Date(),
      }

      const result = await applicationsCollection.insertOne(application)
      res.send(result)
    })

    app.get('/applications/:tuitionId', verifyJWT, async (req, res) => {
      const apps = await applicationsCollection
        .find({ tuitionId: req.params.tuitionId })
        .toArray()
      res.send(apps)
    })

    app.get('/my-applications', verifyJWT, verifyTUTOR, async (req, res) => {
      const apps = await applicationsCollection
        .find({ tutorEmail: req.tokenEmail })
        .toArray()
      res.send(apps)
    })

    /* =========================
       PAYMENTS (Stripe)
    ========================= */
    app.post('/create-checkout-session', async (req, res) => {
      const { title, amount, tuitionId, studentEmail, applicationId } = req.body

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: title },
              unit_amount: amount * 100,
            },
            quantity: 1,
          },
        ],
        mode: 'payment',
        customer_email: studentEmail,
        metadata: { tuitionId, applicationId },
        success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/tuition/${tuitionId}`,
      })

      res.send({ url: session.url })
    })

    app.post('/payment-success', async (req, res) => {
      const { sessionId } = req.body
      const session = await stripe.checkout.sessions.retrieve(sessionId)

      const applicationId = session.metadata.applicationId
      const appData = await applicationsCollection.findOne({
        _id: new ObjectId(applicationId),
      })

      await applicationsCollection.updateOne(
        { _id: new ObjectId(applicationId) },
        { $set: { status: 'approved' } }
      )

      await applicationsCollection.updateMany(
        {
          tuitionId: appData.tuitionId,
          _id: { $ne: new ObjectId(applicationId) },
        },
        { $set: { status: 'rejected' } }
      )

      await paymentsCollection.insertOne({
        tuitionId: appData.tuitionId,
        tutorEmail: appData.tutorEmail,
        studentEmail: session.customer_email,
        amount: session.amount_total / 100,
        transactionId: session.payment_intent,
        createdAt: new Date(),
      })

      res.send({ success: true })
    })

    app.get('/tutor-revenue', verifyJWT, verifyTUTOR, async (req, res) => {
      const payments = await paymentsCollection
        .find({ tutorEmail: req.tokenEmail })
        .toArray()
      res.send(payments)
    })

    console.log('MongoDB connected')
  } finally {
  }
}

run().catch(console.dir)

/* =========================
   Root
========================= */
app.get('/', (req, res) => {
  res.send('eTuition server running 🚀')
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})


