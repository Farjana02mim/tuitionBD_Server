# 🎓 Tuition Management System

A Full-Stack Educational Platform connecting Students seeking qualified private tutors with verified Tutors, featuring Role-Based Access Control, Real-Time Application Tracking, Stripe Payment Gateway Integration, and Interactive Analytics Dashboards.

---

## 🌐 Live Application & Repositories

- **Live URL**: https://ais-pre-hprsliieljrmhnfsu6biuu-466167224879.asia-southeast1.run.app
- **Client Side Repository**: Included in `/client`
- **Server Side Repository**: Included in `/server`

---

## 🎯 Project Purpose

The Tuition Management System streamlines the private tuition hiring lifecycle:
1. **Students** post specific tuition requirements, review tutor applications, and securely hire & pay tutors via Stripe.
2. **Tutors** discover open tuition requirements matching their subject and location expertise, submit applications with expected salaries, and track ongoing tuition jobs and earnings.
3. **Administrators** verify and approve tuition posts, monitor user registrations, manage roles, and review platform revenue analytics.

---

## 🚀 Key Features

### 1. 👥 Multi-Role Authentication & Access Control
- **Email/Password & Google Sign-In** via Firebase Authentication.
- **Strict Server-Side RBAC**: Database-level role verification (`student`, `tutor`, `admin`) prevents frontend role spoofing.
- **Route Guards**: `PrivateRoute`, `StudentRoute`, `TutorRoute`, `AdminRoute` prevent unauthorized access without flickering on page reload.

### 2. 📚 Tuition Marketplace
- **Search & Advanced Filtering**: Filter by subject, class grade, location, budget range, and multi-field keyword search.
- **Sorting**: Lowest budget, highest budget, newest, and oldest.
- **Server-Side Pagination**: Dynamic page navigation with previous/next controls and total page counters.

### 3. 🎓 Student Management
- **Post Tuition Requirements**: Post detailed tuition postings (subject, class, budget, schedule, location).
- **Application Review**: View all tutor applicants per tuition with qualification highlights.
- **Stripe Checkout**: Direct Stripe Payment Gateway integration to accept tutors and automatically reject other pending applicants.
- **Payment History**: View all transaction IDs, dates, and amounts.

### 4. 👨‍🏫 Tutor Portal
- **Tuition Applications**: Apply to approved tuition posts with custom cover details and expected salaries.
- **Application Lifecycle**: Edit or withdraw pending applications; view accepted offers.
- **Ongoing Tuitions**: Contact details and schedules for actively assigned tuition jobs.
- **Revenue Dashboard**: Real-time earnings summary, transaction history, and monthly income statistics.

### 5. 👑 Administrator Dashboard & Analytics
- **Visual Analytics**: Interactive Recharts graphs displaying revenue trends, registration timelines, and tuition statuses.
- **User Management**: Search, filter, modify roles, or delete users.
- **Tuition Moderation**: Approve or reject pending student tuition posts with feedback.
- **Platform Transactions**: Master ledger of all completed payments.

---

## 🛠️ Technology Stack

### Frontend (Client)
- **Framework**: React 18 with Vite
- **Styling**: Tailwind CSS + DaisyUI
- **Icons**: Lucide React
- **Routing**: React Router DOM (v6 Data Router)
- **Data Fetching & Caching**: TanStack React Query + Axios
- **Charts & Visualizations**: Recharts
- **Animations**: Framer Motion
- **Authentication Client**: Firebase SDK v10

### Backend (Server)
- **Runtime**: Node.js
- **Framework**: Express.js (CommonJS)
- **Database**: MongoDB Atlas with native driver (`mongodb`)
- **Token Verification**: Firebase Admin SDK (`firebase-admin`)
- **Payments**: Stripe API SDK (`stripe`)
- **Email Dispatch**: Resend API (`resend`)
- **Security**: Strict CORS policy, ObjectId validation, zero-trust token decoding

---

## ⚙️ Environment Variables Setup

### Client (`/client/.env`)
```env
VITE_FIREBASE_API_KEY=your_firebase_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_firebase_auth_domain
VITE_FIREBASE_PROJECT_ID=your_firebase_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_firebase_storage_bucket
VITE_FIREBASE_MESSAGING_SENDER_ID=your_firebase_messaging_sender_id
VITE_FIREBASE_APP_ID=your_firebase_app_id
VITE_API_URL=http://localhost:3000
```

### Server (`/server/.env`)
```env
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173
DB_USER=your_mongodb_username
DB_PASS=your_mongodb_password
DB_NAME=tuitionManagementDB
FB_SERVICE_KEY=your_base64_encoded_firebase_service_account_json
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
RESEND_API_KEY=re_your_resend_api_key
```

---

## 📦 Package Dependencies

### Client Packages
- `react`, `react-dom`, `react-router-dom`
- `@tanstack/react-query`, `axios`
- `firebase`
- `lucide-react`, `framer-motion`, `recharts`
- `tailwindcss`, `daisyui`

### Server Packages
- `express`, `cors`, `dotenv`
- `mongodb`
- `firebase-admin`
- `stripe`
- `resend`
