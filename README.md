**Live Environement**
[here](https://express-books-ixez.onrender.com/)
**Running the Project**

To run this project on your local machine, follow these steps:

**Prerequisites**
You must have Node.js installed on your computer.

**Installation**

1. Clone the repository
2. Navigate to the project directory
3. Install the project dependencies:
   ```npm install```

**Running the Project**
```npm start```

**Environment Variables**

You can create a .env file in the root directory of your project to set environment-specific variables. They should include-
API_KEY=Your Brevo API Key

SECRET=A Random but complex set of characters for sessions.

MONGODB_URI=

RECAPTCHA_SECRET=Google recaptcha key

RECAPTCHA_SITE_KEY=Google site key

**FUNCTIONALITIES**

**Upload Profile Photo:**
Users can upload a new profile photo.
The uploaded photo is saved and displayed on the user's profile.

![Screenshot 2024-06-15 133259](https://github.com/chistev/Express-Books/assets/115540580/ad22b77c-2928-4d2e-b252-472e69d72991)

**Password Change Functionality**
Hashes the new password and updates it in the database.

**Users Can Delete Their Accounts Securely**
Users can securely delete their accounts, optionally anonymizing their posts and comments, with validation of logged-in status and CSRF tokens for security.

**Admin Book Management Interface**
Users can securely manage books and genres, perform CRUD operations with CSRF token validation and admin checks, and ensure authorization via JWT middleware for admin-specific functionalities in an express-based admin interface.
![Screenshot 2024-06-15 134645](https://github.com/chistev/Express-Books/assets/115540580/ee8ae9dc-b2a1-4aee-9525-0446854f0371)

**Book Details**
Users can view detailed information about a book, including reviews and comments with formatted dates, while logged in status and CSRF token validation ensure secure access and data integrity in an Express-based web application.

![Screenshot 2024-06-15 134851](https://github.com/chistev/Express-Books/assets/115540580/437c4fd1-04db-49a7-bd03-b2fdd57f935b)

**Book Comment Management API:**
Users can fetch, add, and delete comments on books, ensuring CSRF token validation, user authentication, content sanitization, and comprehensive error handling for secure comment management.
![Screenshot 2024-06-15 135124](https://github.com/chistev/Express-Books/assets/115540580/a6e2dfd9-a497-480f-87ce-dc1abbd8a3ec)

**Book Review Like API:**
Users can like or unlike book reviews via API endpoints, ensuring CSRF token validation, user authentication, and error handling for secure management of review likes.

**Favorite Genres Management API: Enables users to view and update their favorite genres with CSRF token validation and user authentication.**
Users can view their selected favorite genres and update them through a form submission, ensuring CSRF token validation and proper error handling for fetching user details and updating the database.
![Screenshot 2024-06-15 135422](https://github.com/chistev/Express-Books/assets/115540580/3b517ddf-ca83-466b-bad9-eacdd013e073)

**Book and Review Management API: Enables users to view their reviewed books, fetch specific review content, and delete reviews with CSRF token validation, user authentication, and content sanitization to prevent XSS attacks.**
Users can view their reviewed books with search capabilities, fetch specific review content for a book, and delete their own reviews with CSRF token validation and user authentication.
![Screenshot 2024-06-15 135614](https://github.com/chistev/Express-Books/assets/115540580/7ef71e87-d67d-4c74-843c-5a5b843f8d9a)

**Forgot Password API: Allows users to request a password reset via email, validating their email address, verifying reCAPTCHA, generating a unique reset token, and sending a password reset email, ensuring secure and user-friendly password recovery flow.**
Users can request a password reset via email by providing their email address. The router verifies the email's existence, validates a reCAPTCHA token, generates a unique token for the password reset link, stores it securely, sends a password reset email to the user, and redirects them to a confirmation page upon successful submission.

**OTP Verification API: Handles OTP verification during user registration, allowing multiple attempts with session-based OTP generation and email delivery for new OTP requests.**
This API endpoint manages the verification of an OTP entered by the user during the registration process. It validates the OTP against the OTP generated and stored in the session. If the OTP matches, the user is redirected to continue with favorite genre selection; otherwise, it allows up to three attempts before generating a new OTP and sending it via email, resetting the attempt count.

**Password Reset Router Summary**
handles the secure password reset process for users, including token validation, password hashing, and JWT authentication token generation.

**Book Review Management**
 handles rendering, writing, editing, and saving book reviews, ensuring authentication, CSRF protection, and proper error handling throughout the process.

 **Search Feature**
 A search feature with suggestions matching the user's input of books in the database.
 ![Screenshot 2024-06-15 140735](https://github.com/chistev/Express-Books/assets/115540580/c83034ea-8c73-47c0-a2be-870465afe422)

 ...and more.











