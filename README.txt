This is the source code for my basic auth example, a website that implements email address and password authentication following best practices. All accounts older than 24 hours are automatically deleted at midnight UTC.

Website: basic-example.auth.pilcrowonpaper.com
Repository: github.com/pilcrowonpaper/basic-example.auth.pilcrowonpaper.com
Created by: pilcrow (pilcrowonpaper.com)
Security: security@pilcrowonpaper.com

Features:

- Email address verification via email code
- Password authentication
- Email address update
- Password update
- Account deletion
- Password reset via email code
- Basic rate limiting

The server is written in Go and uses SQLite as its main database. It's deployed on Railway (railway.com) with emails handled with AWS SES. The frontend is just HTML, JavaScript, and CSS with some basic templating. The website aims to work on the latest version of Chrome, Safari, and Firefox.

You can run the server locally with:

> go run .

All routes and pages are defined in the routes.go file, and APIs are defined in the actions.go file as RPC-like function referred to as "actions."

This project is NOT open to outside contributions. Please file bug reports to the repository's issue tracker. Please email security issues to the security email address listed above. Note that I do not consider user enumerations to be a vulnerability for this website.
