const otpTemplate = ({ otp, appName = "Your App Name" }) => {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8" />
    <title>Email Verification</title>
  </head>
  <body style="margin:0;padding:0;background-color:#f4f6f8;font-family:Arial,Helvetica,sans-serif;">
    
    <table align="center" width="100%" cellpadding="0" cellspacing="0" 
      style="max-width:600px;background:#ffffff;margin:40px auto;border-radius:8px;overflow:hidden;">
      
      <tr>
        <td style="background-color:#4f46e5;padding:20px;text-align:center;color:#ffffff;">
          <h2 style="margin:0;">${appName}</h2>
        </td>
      </tr>

      <tr>
        <td style="padding:30px;color:#333333;">
          <h3>Email Verification</h3>
          <p>Please use the OTP below to verify your email address.</p>

          <div style="text-align:center;margin:30px 0;">
            <span style="display:inline-block;padding:15px 30px;font-size:26px;
              letter-spacing:6px;font-weight:bold;background:#f3f4f6;
              border-radius:8px;color:#111827;">
              ${otp}
            </span>
          </div>

          <p style="font-size:14px;color:#6b7280;">
            This OTP is valid for <strong>5 minutes</strong>.
          </p>

          <p style="font-size:14px;color:#6b7280;">
            ⚠️ Never share this code with anyone.
          </p>
        </td>
      </tr>

      <tr>
        <td style="background:#f9fafb;padding:15px;text-align:center;
          font-size:12px;color:#9ca3af;">
          © ${new Date().getFullYear()} ${appName}. All rights reserved.
        </td>
      </tr>

    </table>

  </body>
  </html>
  `;
};

module.exports = otpTemplate;
