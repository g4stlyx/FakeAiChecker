// Authentication token management
document.addEventListener('DOMContentLoaded', function() {
    // Check if we have a JWT token in URL (from API login)
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (token) {
        // Store the token
        localStorage.setItem('jwtToken', token);
        
        // Remove token from URL (for security)
        const url = new URL(window.location.href);
        url.searchParams.delete('token');
        window.history.replaceState({}, document.title, url.toString());
    }
    
    // Set up AJAX interceptor to add token to all requests
    $(document).ajaxSend(function(e, xhr) {
        const token = localStorage.getItem('jwtToken');
        if (token) {
            xhr.setRequestHeader('Authorization', 'Bearer ' + token);
        }
    });
    
    // Handle admin actions that need authentication
    $('.admin-action').on('click', function(e) {
        if (!localStorage.getItem('jwtToken')) {
            e.preventDefault();
            window.location.href = '/Auth/Login?returnUrl=' + encodeURIComponent($(this).attr('href'));
        }
    });
});
