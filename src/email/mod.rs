use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
};
use liquid::Object;

use crate::{
    configuration::{Email as EmailConfig, EmailTemplate},
    error::{Context, Error},
};

pub struct Email {
    message: Message,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl Email {
    /// Creates a new email
    ///
    /// # Panics
    /// Should never panic.
    ///
    /// This uses an email message builder that returns an error if you don't include a required
    /// field. Since the fields are hardcoded, this should never panic
    ///
    /// # Errors
    /// Will return an error if the smtp relay refuses to upgrade to or downgrades from starttls
    ///
    /// May return an error if there's an issue communicating with the smtp relay
    pub fn new(
        template: &EmailTemplate,
        globals: &Object,
        config: &EmailConfig,
        recipient: Mailbox,
    ) -> Result<Self, Error> {
        let parser = liquid::ParserBuilder::with_stdlib()
            .build()
            .context("Building a liquid parser")?;

        let html_body = parser
            .parse_file(&template.html_body)
            .context("Parsing an html email template")?
            .render(&globals)
            .context("Rendering an html email template")?;

        let plaintext_body = parser
            .parse_file(&template.fallback_body)
            .context("Parsing a plaintext email template")?
            .render(&globals)
            .context("Rendering a plaintext email template")?;

        let message = Message::builder()
            .from(config.send_from.clone())
            .reply_to(config.reply_to.clone())
            .to(recipient)
            .subject(template.subject.clone())
            .multipart(MultiPart::alternative_plain_html(plaintext_body, html_body))
            .expect("lettre dependency broken");

        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.relay)
            .context("Connecting to smtp relay")?
            .credentials(config.credentials.clone())
            .build();

        Ok(Self { message, mailer })
    }

    /// Sends the email
    ///
    /// # Errors
    /// Will return an error if the smtp relay cannot forward the message
    ///
    /// May return an error if there's an issue communicating with the smtp relay
    pub async fn send(self) -> Result<(), Error> {
        let response = self
            .mailer
            .send(self.message)
            .await
            .context("Sending email")?;

        if response.is_positive() {
            Ok(())
        } else {
            Err(Error::new(
                crate::error::ErrorKind::EmailFailed,
                "Could not send email".into(),
                "Sending email",
            ))
        }
    }
}
