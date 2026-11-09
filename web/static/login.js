// Login page script: the password "eye". Served from /static/ (a public path)
// so the login page runs under the same script-src 'self' CSP as the dashboard.
document.addEventListener('click', e => {
    if (!e.target.closest('[data-action="togglePw"]')) return;
    const p = document.getElementById('lpw');
    p.type = p.type === 'password' ? 'text' : 'password';
});
