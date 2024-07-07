export function getHTMLForEmailVerification(firstName, verificationLink) {
    return `
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }
        .email-container {
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0px 0px 10px 0px rgba(0,0,0,0.1);
        }
        .email-content {
            margin-top: 20px;
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            margin-top: 20px;
            color: #fff;
            background-color: #3498db;
            border-radius: 5px;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <h2>Welcome to Elachi!</h2>
        <div class="email-content">
            <p>Dear ${firstName},</p>
            <p>Thank you for signing up. Please verify your email by clicking the link below:</p>
            <a href=${verificationLink} class="button">Verify Email</a>
            <p>Thank you,<br>Elachi</p>
        </div>
    </div>
</body>
</html>
`;
}
