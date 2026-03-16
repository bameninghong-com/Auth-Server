import nodemailer, { Transporter } from 'nodemailer'
import { env } from '../config/env'

let transporter: Transporter

export function getMailTransporter(): Transporter {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host:   env.SMTP_HOST,
      port:   env.SMTP_PORT,
      secure: env.SMTP_SECURE,  // false für Port 587 (STARTTLS)
      auth:   env.SMTP_USER && env.SMTP_PASS
        ? { user: env.SMTP_USER, pass: env.SMTP_PASS }
        : undefined,
      tls: {
        // STARTTLS für Port 587
        ciphers: 'SSLv3',
        rejectUnauthorized: false,
      },
    })
  }
  return transporter
}

export async function sendVerificationEmail(opts: {
  to:       string
  token:    string
  tenantSlug: string
}): Promise<void> {
  const link = `${env.APP_URL}/auth/verify-email?token=${opts.token}&tenant=${opts.tenantSlug}`

  await getMailTransporter().sendMail({
    from:    env.SMTP_FROM,
    to:      opts.to,
    subject: 'Confirm your email address',
    text:    `Click the link to verify your email:\n\n${link}\n\nThis link expires in 24 hours.`,
    html:    `
      <p>Click the button below to verify your email address.</p>
      <a href="${link}" style="
        display:inline-block;padding:12px 24px;
        background:#4F46E5;color:#fff;
        border-radius:6px;text-decoration:none;font-weight:500
      ">Verify Email</a>
      <p style="color:#888;font-size:12px">This link expires in 24 hours.</p>
    `,
  })
}

export async function sendPasswordResetEmail(opts: {
  to:    string
  token: string
  tenantSlug: string
}): Promise<void> {
  const link = `${env.APP_URL}/auth/reset-password?token=${opts.token}&tenant=${opts.tenantSlug}`

  await getMailTransporter().sendMail({
    from:    env.SMTP_FROM,
    to:      opts.to,
    subject: 'Reset your password',
    text:    `Click the link to reset your password:\n\n${link}\n\nThis link expires in 1 hour.`,
    html:    `
      <p>You requested a password reset. Click the button below.</p>
      <a href="${link}" style="
        display:inline-block;padding:12px 24px;
        background:#4F46E5;color:#fff;
        border-radius:6px;text-decoration:none;font-weight:500
      ">Reset Password</a>
      <p style="color:#888;font-size:12px">
        This link expires in 1 hour. If you didn't request this, ignore this email.
      </p>
    `,
  })
}
