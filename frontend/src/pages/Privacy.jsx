import LegalLayout, { Section } from "@/components/LegalLayout";

const Privacy = () => {
  return (
    <LegalLayout title="Privacy Policy" updated="June 1, 2026" testid="privacy-page">
      <p className="text-sm leading-relaxed">
        This Privacy Policy describes how IronClaw-Security ("IronClaw", "we",
        "us", or "our"), a service operated by Universal Rejuvenation Inc. — The
        Enlightenism Organization, collects, uses, and protects your information
        when you use our platform, website, and related services (collectively,
        the "Service"). By using the Service, you agree to the practices
        described in this policy.
      </p>

      <Section heading="1. Information We Collect">
        <p>We collect the following categories of information:</p>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <strong className="text-white">Account information</strong> — your
            email address and a securely hashed password used to authenticate
            your account.
          </li>
          <li>
            <strong className="text-white">Usage &amp; security telemetry</strong>{" "}
            — verdicts, risk scores, threat types, timestamps, unit consumption,
            and metadata generated as your AI agents are protected by the
            Service.
          </li>
          <li>
            <strong className="text-white">Billing information</strong> —
            payments are processed by our third-party payment processor (Stripe).
            We do not store full card numbers on our servers.
          </li>
          <li>
            <strong className="text-white">Technical data</strong> — IP address,
            browser type, and similar diagnostic information.
          </li>
        </ul>
      </Section>

      <Section heading="2. How We Use Your Information">
        <p>We use the information we collect to:</p>
        <ul className="list-disc space-y-1 pl-5">
          <li>Provide, operate, and secure the Service;</li>
          <li>Authenticate users and protect against unauthorized access;</li>
          <li>Process payments and maintain your unit wallet balance;</li>
          <li>Generate audit trails, analytics, and security verdicts;</li>
          <li>Detect, prevent, and respond to security incidents and abuse;</li>
          <li>Comply with legal obligations.</li>
        </ul>
      </Section>

      <Section heading="3. Data Security">
        <p>
          Security is the core of our business. Passwords are hashed using
          industry-standard algorithms, data is transmitted over encrypted
          connections, and tenant data is logically isolated so that no
          organization can access another organization's security context. No
          method of transmission or storage is perfectly secure, but we apply
          commercially reasonable safeguards to protect your data.
        </p>
      </Section>

      <Section heading="4. Data Retention">
        <p>
          We retain audit logs, incident records, and account data for as long
          as your account is active or as needed to provide the Service, comply
          with legal obligations, resolve disputes, and enforce agreements. You
          may request deletion of your account data at any time.
        </p>
      </Section>

      <Section heading="5. Third-Party Services">
        <p>
          We rely on trusted third-party providers — including Stripe for
          payment processing — that process limited data on our behalf. These
          providers are bound by their own privacy and security obligations.
        </p>
      </Section>

      <Section heading="6. Your Rights">
        <p>
          Depending on your jurisdiction, you may have the right to access,
          correct, export, or delete your personal data, and to object to or
          restrict certain processing. To exercise these rights, contact us using
          the details below.
        </p>
      </Section>

      <Section heading="7. Changes to This Policy">
        <p>
          We may update this Privacy Policy from time to time. Material changes
          will be reflected by updating the "Last updated" date above. Continued
          use of the Service after changes constitutes acceptance of the revised
          policy.
        </p>
      </Section>

      <Section heading="8. Contact Us">
        <p>
          For privacy questions or requests, contact us at{" "}
          <span className="text-[#38BDF8]">privacy@ironclaw-security.com</span>.
        </p>
      </Section>
    </LegalLayout>
  );
};

export default Privacy;
