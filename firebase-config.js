// ==================================================================================
// FIREBASE CONFIGURATION — NACOS PLASU PAYMENT PORTAL
// ==================================================================================
// Steps to activate:
//  1. Go to https://console.firebase.google.com
//  2. Create a project (free Spark plan — no credit card needed)
//  3. Add a Web App, copy the firebaseConfig object below and replace the values
//  4. In Firestore → Rules, set:
//       rules_version = '2';
//       service cloud.firestore {
//         match /databases/{database}/documents {
//           match /{document=**} { allow read, write: if true; }
//         }
//       }
//     (tighten rules before going live)
// ==================================================================================

const firebaseConfig = {
    apiKey:            "REPLACE_WITH_YOUR_API_KEY",
    authDomain:        "REPLACE_WITH_YOUR_AUTH_DOMAIN",
    projectId:         "REPLACE_WITH_YOUR_PROJECT_ID",
    storageBucket:     "REPLACE_WITH_YOUR_STORAGE_BUCKET",
    messagingSenderId: "REPLACE_WITH_YOUR_MESSAGING_SENDER_ID",
    appId:             "REPLACE_WITH_YOUR_APP_ID"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Firestore database instance — used throughout app.js
const db = firebase.firestore();

// Flag: true when Firebase is properly configured (not placeholder values)
const FIREBASE_ENABLED = !firebaseConfig.apiKey.startsWith('REPLACE');
