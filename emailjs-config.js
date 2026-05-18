// ==================================================================================
// EMAILJS CONFIGURATION — NACOS PLASU PAYMENT PORTAL
// ==================================================================================
// EmailJS sends emails directly from the browser — no backend server needed.
// Free plan: 200 emails/month
//
// Setup steps:
//  1. Go to https://www.emailjs.com and create a free account
//  2. Add an Email Service (Gmail recommended) → copy the Service ID
//  3. Create Email Templates for each notification type below:
//
//     Template: nacos_welcome
//       Subject: Welcome to NACOS PLASU — Registration Successful
//       Body variables: {{to_name}}, {{matric_number}}, {{level}}
//
//     Template: nacos_payment_submitted
//       Subject: Payment Submitted — Pending Verification
//       Body variables: {{to_name}}, {{matric_number}}, {{level}}, {{amount}}, {{reference}}, {{date}}
//
//     Template: nacos_payment_approved
//       Subject: ✅ Payment Approved — NACOS PLASU
//       Body variables: {{to_name}}, {{matric_number}}, {{level}}, {{amount}}, {{reference}}, {{receipt_no}}
//
//     Template: nacos_payment_rejected
//       Subject: ❌ Payment Rejected — NACOS PLASU
//       Body variables: {{to_name}}, {{matric_number}}, {{level}}, {{amount}}, {{reference}}
//
//     Template: nacos_password_reset
//       Subject: Password Reset — NACOS PLASU
//       Body variables: {{to_name}}, {{matric_number}}
//
//  4. Copy your Public Key from Account → API Keys
//  5. Replace the placeholder values below
// ==================================================================================

const EMAILJS_CONFIG = {
    publicKey:   'REPLACE_WITH_YOUR_PUBLIC_KEY',   // Account → API Keys
    serviceId:   'REPLACE_WITH_YOUR_SERVICE_ID',   // Email Services → Service ID
    templates: {
        welcome:           'nacos_welcome',
        paymentSubmitted:  'nacos_payment_submitted',
        paymentApproved:   'nacos_payment_approved',
        paymentRejected:   'nacos_payment_rejected',
        passwordReset:     'nacos_password_reset'
    }
};

// Flag: true when EmailJS is properly configured (not placeholder values)
const EMAILJS_ENABLED = !EMAILJS_CONFIG.publicKey.startsWith('REPLACE');

// Initialise EmailJS SDK if configured
if (EMAILJS_ENABLED) {
    emailjs.init({ publicKey: EMAILJS_CONFIG.publicKey });
    console.info('NACOS: EmailJS initialised');
} else {
    console.info('NACOS: EmailJS not configured — email notifications disabled');
}
