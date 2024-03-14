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
    const accessToken = sessionStorage.getItem('access_token');
    if (!accessToken) {
        return null;
    }
    const tokenClaims = parseJwt(accessToken);
    if (tokenClaims.exp * 1000 < Date.now()) {
        // Access token is expired, redirect to login
        login();
        return null;
    } else {
        return accessToken;
    }
}

// Function to store token in sessionStorage
function storeToken(token) {
    sessionStorage.setItem('access_token', token);
}

// Function to clear token from sessionStorage
function clearToken() {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('id_token');
    sessionStorage.removeItem('tokenClaims');
}

// Function to handle login
function login() {
    // Store the current page URL before redirecting
    storeCurrentPageURL();
    // Redirect user to Azure AD B2C for authentication
    window.location.href = 'https://resumedev.b2clogin.com/resumedev.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_SignUpSignIn&client_id=eb4669a7-4113-460f-9e84-2b409eac8af0&nonce=defaultNonce&redirect_uri=https%3A%2F%2Fresume.jon-polansky.com%2F.auth%2Flogin%2Faadb2c%2Fcallback&scope=openid&response_type=id_token%20token&prompt=login&state=' + encodeURIComponent(window.location.href);
}

// Function to handle logout
function logout() {
    clearToken();
    // Redirect user to logout endpoint or home page
    window.location.href = '/';
}

// Function to handle the authentication callback
function handleAuthenticationCallback() {
    // Parse fragment parameters from URL
    const urlParams = new URLSearchParams(window.location.hash.substring(1));
    const accessToken = urlParams.get('access_token');
    const idToken = urlParams.get('id_token');
    const error = urlParams.get('error');
    const redirectFrom = urlParams.get('state');

    if (accessToken) {
        // Authentication successful, store the access token securely (e.g., in session storage)
        sessionStorage.setItem('access_token', accessToken);

        // If an ID token is present, parse its claims and store them
        if (idToken) {
            sessionStorage.setItem('id_token', idToken);
            const tokenClaims = parseJwt(idToken);
            if (tokenClaims) {
                sessionStorage.setItem('tokenClaims', JSON.stringify(tokenClaims));
            }
        }

        // Redirect user back to the original page or perform additional actions
        window.location.href = decodeURIComponent(redirectFrom) || '/';
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

    displayTokenClaims();
}

function displayTokenClaims() {
    // Get ID token from sessionStorage
    const idToken = sessionStorage.getItem('id_token');
    if (idToken) {
        // Parse ID token to get claims
        const tokenClaims = parseJwt(idToken);
        if (tokenClaims) {
            // Display claims dynamically
            const displayNameElement = document.getElementById('displayName');
            if (displayNameElement) {
                displayNameElement.innerText = tokenClaims.name || 'No Data';
            }
            const emailAddressesElement = document.getElementById('emailAddresses');
            if (emailAddressesElement) {
                emailAddressesElement.innerText = (tokenClaims.emails && tokenClaims.emails.join(', ')) || 'No Data';
            }
            const givenNameElement = document.getElementById('givenName');
            if (givenNameElement) {
                givenNameElement.innerText = tokenClaims.given_name || 'No Data';
            }
            const elevatedElement = document.getElementById('elevated');
            if (elevatedElement) {
                elevatedElement.innerText = tokenClaims.extension_Elevated || 'No Data';
            }
        } else {
            console.error('Token claims not found.');
        }
    } else {
        console.error('ID token not found.');
    }
}