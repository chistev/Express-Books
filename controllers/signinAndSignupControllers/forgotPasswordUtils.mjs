import User from '../../models/User.mjs'; 

// Function to store the token in the database
async function storeTokenInDatabase(email, token) {
    try {
        // Calculate expiration time (e.g., 1 hour from now)
        const expirationTime = new Date();
        expirationTime.setHours(expirationTime.getHours() + 1); // Set expiration to 1 hour from now

        // Update the user document with the token
        await User.updateOne({ email }, { passwordResetToken: token, passwordResetTokenExpires: expirationTime });
        console.log('Token stored in the database for email:', email);
        console.log("token sent is: " + token)
    } catch (error) {
        console.error('Error storing token in the database:', error);
        // Handle the error appropriately
    }
}

// Function to send password reset email
async function sendPasswordResetEmail(email, resetUrl, fullName) {
    const apiKey = process.env.API_KEY;
    const apiUrl = 'https://api.brevo.com/v3/smtp/email';
    const body = {
        sender: {
            name: 'chistev',
            email: 'stephenowabie@gmail.com'
        },
        to: [
            {
                email: email,
                name: fullName
            }
        ],
        subject: 'Password Reset Request',
        htmlContent: `<html><head></head><body><p>Hello ${fullName},</p><p>You can change your Myreads password by clicking below.</p><p><a href="${resetUrl}">Change Password</a></p><p>If you did not request that your password be reset, ignore this email and your password will remain the same.</p></body></html>`
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
        console.error('Failed to send email:', error);
        throw new Error('Failed to send email');
    }
}

export { storeTokenInDatabase, sendPasswordResetEmail };