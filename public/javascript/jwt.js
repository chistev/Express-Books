// Function to retrieve JWT token from cookies
function getJwtToken() {
    const name = 'token=';
    const decodedCookie = decodeURIComponent(document.cookie);
    const cookieArray = decodedCookie.split(';');
    for (let i = 0; i < cookieArray.length; i++) {
        let cookie = cookieArray[i];
        while (cookie.charAt(0) === ' ') {
            cookie = cookie.substring(1);
        }
        if (cookie.indexOf(name) === 0) {
            const token = cookie.substring(name.length, cookie.length);
            console.log('JWT token retrieved from cookies:', token);
            return token;
        }
    }
    console.log('No JWT token found in cookies.');
    return '';
}

// Function to store JWT token in local storage
function storeJwtTokenInLocalStorage() {
    const token = getJwtToken();
    if (token) {
        localStorage.setItem('jwtToken', token);
        console.log('JWT token stored in local storage:', token);
    } else {
        console.log('No JWT token found to store in local storage.');
    }
}

// Call the function to store JWT token in local storage when the page loads
storeJwtTokenInLocalStorage();
