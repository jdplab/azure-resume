// Function to parse JWT token
function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error('Error parsing JWT token:', error);
        return null;
    }
}

function storeCurrentPageURL() {
    sessionStorage.setItem('redirectFrom', window.location.href);
}

// Function to retrieve token from sessionStorage
function getToken() {
    return sessionStorage.getItem('access_token');
}

// Function to store token in sessionStorage
function storeToken(token) {
    sessionStorage.setItem('access_token', token);
}

// Function to clear token from sessionStorage
function clearToken() {
    sessionStorage.removeItem('access_token');
}

// Function to handle login
function login() {
    // Store the current page URL before redirecting
    storeCurrentPageURL();
    // Redirect user to Azure AD B2C for authentication
    window.location.href = 'https://resumedev.b2clogin.com/resumedev.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_SignUpSignIn&client_id=eb4669a7-4113-460f-9e84-2b409eac8af0&nonce=defaultNonce&redirect_uri=https%3A%2F%2Fresume.jon-polansky.com%2F.auth%2Flogin%2Faadb2c%2Fcallback&scope=openid&response_type=code&prompt=login&redirectFrom=' + encodeURIComponent(window.location.href);
}

// Function to handle logout
function logout() {
    clearToken();
    // Redirect user to logout endpoint or home page
    window.location.href = '/';
}

// Function to handle the authentication callback
function handleAuthenticationCallback() {
    // Parse query parameters from URL
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    const redirectFrom = urlParams.get('redirectFrom');

    if (code) {
        // Authentication successful, store the code securely (e.g., in local storage)
        localStorage.setItem('authCode', code);
        // Redirect user back to the original page or perform additional actions
        window.location.href = redirectFrom || '/';
        
        // Retrieve token from local storage
        const token = localStorage.getItem('authCode');
        
        // Parse token claims
        const tokenClaims = parseJwt(token);
        
        // Do something with the token claims
        if (tokenClaims) {
            console.log('Token claims:', tokenClaims);
            // Example: Store claims in session storage
            sessionStorage.setItem('tokenClaims', JSON.stringify(tokenClaims));
        }
    } else if (error) {
        // Authentication failed, handle the error (e.g., display error message)
        console.error('Authentication error:', error);
        alert('Authentication failed. Please try again.');
        // Redirect user to the home page or another appropriate page
        window.location.href = '/';
    } else {
        // Unexpected state, handle appropriately (e.g., redirect to home page)
        window.location.href = '/';
    }
}

function displayTokenClaims() {
    // Get token from sessionStorage
    const token = getToken();
    if (token) {
        // Parse token to get claims
        const tokenClaims = parseJwt(token);
        if (tokenClaims) {
            // Display claims dynamically
            document.getElementById('displayName').innerText = tokenClaims.name || 'No Data';
            document.getElementById('emailAddresses').innerText = tokenClaims.emails.join(', ') || 'No Data';
            document.getElementById('givenName').innerText = tokenClaims.given_name || 'No Data';
            document.getElementById('elevated').innerText = tokenClaims.extension_Elevated || 'No Data';
        } else {
            console.error('Token claims not found.');
        }
    } else {
        console.error('Access token not found.');
    }
}

displayTokenClaims();