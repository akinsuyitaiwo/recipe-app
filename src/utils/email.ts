import config from "../config";
import sgMail from "@sendgrid/mail"

sgMail.setApiKey(config.SENDGRID_API_KEY as string);

const msg: any = {
  from: `Donda <${config.SENDGRID_EMAIL}>`,
  mail_settings: { sandbox_mode: { enable: false } }
};

() => {
  msg.mail_settings.sandbox_mode.enable = true;
};

const sendEmail = async (email: string, subject: string, message: string) => {
  try {
    msg.to = email;
    msg.subject = subject;
    msg.text = message;
    await sgMail.send(msg);
    console.log("message sent...");
  } catch (err) {
    return err;
  }
};

export default sendEmail;