    function checkLoginStatus() {
        const token = localStorage.getItem('token');
        const submitArticleLink = document.getElementById('submitArticleLink');
        const loginLink = document.getElementById('loginLink');
        const registerLink = document.getElementById('registerLink');
        const logoutLink = document.getElementById('logoutLink');

        if (token) {
            submitArticleLink.style.display = 'block';
            loginLink.style.display = 'none';
            registerLink.style.display = 'none';
            logoutLink.style.display = 'block';
        } else {
            submitArticleLink.style.display = 'none';
            loginLink.style.display = 'block';
            registerLink.style.display = 'block';
            logoutLink.style.display = 'none';
        }
    }

    document.getElementById('logoutButton')?.addEventListener('click', function (e) {
        e.preventDefault();
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('userId');
        window.location.href = '/';
    });

    window.onload = checkLoginStatus;
