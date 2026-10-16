// Deliberately synthetic example; no external hosts are contacted.
fetch('/api/v1/users?token=DO_NOT_EXPOSE');
axios.get('https://example.test/v1/profile');
fetch('/api/' + userID); // dynamic; intentionally omitted
