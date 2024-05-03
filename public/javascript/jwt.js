function storeToken(token) {
    localStorage.setItem('token', token);
}

function getToken() {
    return localStorage.getItem('token');
}

// Example function to make an authenticated request
async function fetchData() {
    const token = getToken();

    try {
        const response = await fetch('/api/data', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}` // Include token in request headers
            }
        });

        const data = await response.json();
        console.log('Data:', data);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}