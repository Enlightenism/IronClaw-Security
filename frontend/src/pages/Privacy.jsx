import LegalLayout, { Section } from "@/components/LegalLayout";

const Privacy = () => {
  return (
    <LegalLayout title="Privacy Policy" updated="June 1, 2026" testid="privacy-page">
      <p className="text-sm leading-relaxed">
        This Privacy Policy ("Policy") describes how IronClaw-Security
        ("IronClaw-Security", "we", "us", or "our") collects, uses, discloses,
        and safeguards information when you access or use our platform, website,
        APIs, and related services (collectively, the "Service"). By creating an
        account, accessing, or using the Service, you acknowledge that you have
        read, understood, and agree to be bound by this Policy. If you do not
        agree, you must not access or use the Service.
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
            install tokens, and metadata generated as your AI agents are
            protected by the Service.
          </li>
          <li>
            <strong className="text-white">Billing information</strong> —
            payments are processed by our third-party payment processor (Stripe).
            We do not store full payment card numbers on our servers.
          </li>
          <li>
            <strong className="text-white">Technical data</strong> — IP address,
            device and browser type, and similar diagnostic information.
          </li>
        </ul>
      </Section>

      <Section heading="2. How We Use Your Information">
        <p>We use the information we collect to:</p>
        <ul className="list-disc space-y-1 pl-5">
          <li>Provide, operate, maintain, and secure the Service;</li>
          <li>Authenticate users and protect against unauthorized access;</li>
          <li>Process payments and maintain your unit wallet balance;</li>
          <li>Generate audit trails, analytics, and security verdicts;</li>
          <li>Detect, prevent, investigate, and respond to security incidents, fraud, and abuse;</li>
          <li>Improve and develop new features; and</li>
          <li>Comply with legal, regulatory, and contractual obligations.</li>
        </ul>
      </Section>

      <Section heading="3. Legal Bases & Disclosures">
        <p>
          We process information as necessary to perform our contract with you,
          to pursue our legitimate interests in operating and securing the
          Service, to comply with law, and where required, with your consent. We
          may disclose information to service providers acting on our behalf, to
          comply with legal process or lawful requests, to enforce our
          agreements, to protect the rights, property, and safety of
          IronClaw-Security and others, and in connection with a merger,
          acquisition, financing, or sale of assets.
        </p>
      </Section>

      <Section heading="4. Data Security">
        <p>
          Security is the core of our business. Passwords are hashed using
          industry-standard algorithms, data is transmitted over encrypted
          connections, and tenant data is logically isolated so that no
          organization can access another organization's security context. While
          we apply commercially reasonable administrative, technical, and
          physical safeguards, no method of transmission or storage is perfectly
          secure, and we cannot and do not guarantee the absolute security of any
          information. You provide information at your own risk.
        </p>
      </Section>

      <Section heading="5. Data Retention">
        <p>
          We retain audit logs, incident records, and account data for as long as
          your account is active or as needed to provide the Service, comply with
          legal obligations, resolve disputes, prevent fraud and abuse, and
          enforce our agreements. We may retain de-identified or aggregated data
          indefinitely.
        </p>
      </Section>

      <Section heading="6. Third-Party Services">
        <p>
          We rely on trusted third-party providers — including Stripe for payment
          processing — that process limited data on our behalf and under their
          own privacy and security obligations. We are not responsible for the
          privacy practices, content, or actions of any third party, and your use
          of such third-party services is governed by their respective terms and
          policies.
        </p>
      </Section>

      <Section heading="7. Your Choices & Rights">
        <p>
          Depending on your jurisdiction, you may have the right to access,
          correct, export, restrict, or delete certain personal data, and to
          object to certain processing. We will respond to verified requests as
          required by applicable law. Exercising these rights will not affect the
          lawfulness of processing carried out before your request.
        </p>
      </Section>

      <Section heading="8. International Transfers">
        <p>
          Your information may be processed and stored in jurisdictions other
          than your own, which may have different data protection laws. By using
          the Service, you consent to such transfer, processing, and storage.
        </p>
      </Section>

      <Section heading="9. Children's Privacy">
        <p>
          The Service is not directed to individuals under the age of 18, and we
          do not knowingly collect personal information from children. If we
          learn that we have collected such information, we will delete it.
        </p>
      </Section>

      <Section heading="10. Changes to This Policy">
        <p>
          We may update this Policy at any time, in our sole discretion. Material
          changes will be reflected by updating the "Last updated" date above.
          Your continued use of the Service after any change constitutes
          acceptance of the revised Policy.
        </p>
      </Section>

      <Section heading="11. No Liability; Assumption of Risk; Limitation">
        <p>
          The Service and all information provided through it are made available
          on an "as is" and "as available" basis, without warranties of any kind,
          whether express, implied, statutory, or otherwise, including any implied
          warranties of merchantability, fitness for a particular purpose,
          accuracy, and non-infringement. IronClaw-Security does not warrant that
          the Service will detect or prevent all threats, that it will be
          uninterrupted, timely, secure, or error-free, or that any data will not
          be lost, altered, or accessed without authorization.
        </p>
        <p>
          To the maximum extent permitted by applicable law, IronClaw-Security and
          its officers, directors, employees, contractors, agents, licensors, and
          affiliates shall not be liable for any indirect, incidental, special,
          consequential, exemplary, or punitive damages, or for any loss of
          profits, revenues, data, goodwill, or other intangible losses, arising
          out of or relating to your use of (or inability to use) the Service or
          this Policy, whether based in contract, tort (including negligence),
          strict liability, or any other legal theory, even if advised of the
          possibility of such damages. In no event shall the aggregate liability
          of IronClaw-Security exceed the greater of (a) the total amounts you
          paid to IronClaw-Security in the twelve (12) months preceding the event
          giving rise to the claim, or (b) one hundred U.S. dollars (USD $100).
          You acknowledge and accept that you assume all risk arising from your
          use of the Service and any reliance on its verdicts or outputs.
        </p>
      </Section>

      <Section heading="12. Indemnification">
        <p>
          You agree to defend, indemnify, and hold harmless IronClaw-Security and
          its officers, directors, employees, contractors, agents, licensors, and
          affiliates from and against any and all claims, damages, obligations,
          losses, liabilities, costs, and expenses (including reasonable
          attorneys' fees) arising from or related to your use of the Service,
          your data, your violation of this Policy or applicable law, or your
          infringement of any third-party right.
        </p>
      </Section>

      <Section heading="13. Governing Law, Arbitration & Class Action Waiver">
        <p>
          This Policy and any dispute arising out of or relating to it or the
          Service shall be governed by the laws of the State of Delaware, USA,
          without regard to conflict-of-laws principles. Any dispute shall be
          resolved exclusively through final and binding individual arbitration,
          and not in court, except that either party may seek injunctive relief
          for intellectual-property or unauthorized-access matters.{" "}
          <strong className="text-white">
            You and IronClaw-Security each waive any right to a jury trial and any
            right to participate in a class, collective, or representative action.
          </strong>{" "}
          Any claim must be brought within one (1) year after it arises, or it is
          permanently barred. If any provision of this Policy is held
          unenforceable, the remaining provisions remain in full force and
          effect, and this Policy constitutes the entire agreement regarding its
          subject matter.
        </p>
      </Section>

      <Section heading="14. Contact Us">
        <p>
          For privacy questions or requests, contact us at{" "}
          <span className="text-[#38BDF8]">privacy@ironclaw-security.com</span>.
        </p>
      </Section>
    </LegalLayout>
  );
};

export default Privacy;
