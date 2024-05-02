import fetch from 'node-fetch';

// Function to validate email format using regular expression
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function generateOTP() {
    const digits = '0123456789';
    let otp = '';
    for (let i = 0; i < 6; i++) {
        otp += digits[Math.floor(Math.random() * 10)];
    }
    return otp;
}

// Function to send email using Brevo API
async function sendEmail(email, fullName, otp) {
    const apiKey = process.env.API_KEY;
    const apiUrl = 'https://api.brevo.com/v3/smtp/email';
    const body = {
        sender: {
            name: 'Chistev',
            email: 'stephenowabie@gmail.com'
        },
        to: [
            {
                email: email,
                name: fullName
            }
        ],

        subject: 'Your OTP for registration',
        htmlContent: `<html><head></head><body><p>Hello,</p><p>Your OTP for registration is: ${otp}</p></body></html>`
    };
    try {
    const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'text/html',
            'Accept': 'application/json',
            'api-key': apiKey
        },
        body: JSON.stringify(body),
    });

    if (!response.ok) {
        throw new Error('Failed to send email');
    }
} catch (error) {
    throw new Error('Failed to send email');
}
}

export { validateEmail, generateOTP, sendEmail };