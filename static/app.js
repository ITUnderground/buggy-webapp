// Fetches a user profile and shows it in the #profile element.
// The uid is passed in from the page; the 'auth' cookie rides along
// automatically. (Try changing the id in the request to read someone
// else's profile — that's the IDOR in /api/profile.)
async function loadProfile(uid) {
  const r = await fetch('/api/profile?id=' + uid);
  document.getElementById('profile').textContent =
    JSON.stringify(await r.json(), null, 2);
}
