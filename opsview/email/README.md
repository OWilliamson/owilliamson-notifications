# Email with notes (Opsview)

Sends notification emails using Opsview/Nagios environment variables and **template-based** content. Fetches host/service notes from the Opsview/Runtime schema and includes them in the email body.

- **notify_by_email_with_notes.pl** – Main Perl script: picks template by `OPSVIEW_OBJECTTYPE` (opsview vs nagios), resolves contact email from `OPSVIEW_CONTACTEMAIL` or `NAGIOS_CONTACTEMAIL`, and processes the chosen template with note data.
- **notify_by_email_notes** – Same behaviour under a different name (sends email using template and notes).
- **com.opsview.notificationmethods.email.tt** – Template Toolkit template for the default Nagios-style email (references Opsview business-service and component types).
