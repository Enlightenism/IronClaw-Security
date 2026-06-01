import LegalLayout, { Section } from "@/components/LegalLayout";

const Terms = () => {
  return (
    <LegalLayout title="Terms of Service" updated="June 1, 2026" testid="terms-page">
      <p className="text-sm leading-relaxed">
        These Terms of Service ("Terms") govern your access to and use of
        IronClaw-Security (the "Service"), operated by Universal Rejuvenation
        Inc. — The Enlightenism Organization ("we", "us", or "our"). By creating
        an account or using the Service, you agree to be bound by these Terms. If
        you do not agree, do not use the Service.
      </p>

      <Section heading="1. Eligibility & Accounts">
        <p>
          You must be at least 18 years old and capable of forming a binding
          contract to use the Service. You are responsible for maintaining the
          confidentiality of your account credentials and for all activity that
          occurs under your account.
        </p>
      </Section>

      <Section heading="2. The Service">
        <p>
          IronClaw-Security provides an enforcement layer that inspects and
          governs AI agent activity, including prompt inspection, action
          guarding, policy enforcement, sandboxed execution, and auditing. The
          Service is provided to help reduce risk but does not guarantee that all
          threats will be detected or prevented.
        </p>
      </Section>

      <Section heading="3. Units, Billing & Payments">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            The Service operates on a prepaid, usage-based "unit" model. Units
            are consumed as your agents are protected.
          </li>
          <li>
            Unit purchases are one-time charges with no subscription or recurring
            billing. Pricing is displayed at checkout.
          </li>
          <li>
            Payments are processed securely by Stripe. You authorize us to charge
            your selected payment method for purchases you initiate.
          </li>
          <li>
            Except where required by law, unit purchases are non-refundable.
            Purchased units do not expire while your account remains active.
          </li>
        </ul>
      </Section>

      <Section heading="4. Acceptable Use">
        <p>You agree not to:</p>
        <ul className="list-disc space-y-1 pl-5">
          <li>Use the Service for any unlawful or malicious purpose;</li>
          <li>
            Attempt to bypass, disable, or interfere with the Service's security
            or enforcement layers;
          </li>
          <li>
            Access another organization's data or attempt to break tenant
            isolation;
          </li>
          <li>Reverse engineer or resell the Service without authorization.</li>
        </ul>
      </Section>

      <Section heading="5. Intellectual Property">
        <p>
          The Service, including all software, design, and content, is owned by
          us and our licensors and is protected by intellectual property laws.
          You retain ownership of the data you submit, and you grant us a limited
          license to process it solely to provide the Service.
        </p>
      </Section>

      <Section heading="6. Disclaimer of Warranties">
        <p>
          The Service is provided "as is" and "as available" without warranties
          of any kind, whether express or implied, including fitness for a
          particular purpose and non-infringement. We do not warrant that the
          Service will be uninterrupted, error-free, or fully secure.
        </p>
      </Section>

      <Section heading="7. Limitation of Liability">
        <p>
          To the maximum extent permitted by law, we shall not be liable for any
          indirect, incidental, special, consequential, or punitive damages, or
          for any loss of data or profits, arising out of your use of the
          Service. Our total liability for any claim shall not exceed the amount
          you paid us in the twelve months preceding the claim.
        </p>
      </Section>

      <Section heading="8. Termination">
        <p>
          We may suspend or terminate your access to the Service at any time if
          you violate these Terms. You may stop using the Service and request
          account deletion at any time.
        </p>
      </Section>

      <Section heading="9. Changes to These Terms">
        <p>
          We may revise these Terms from time to time. Material changes will be
          reflected by updating the "Last updated" date above. Continued use of
          the Service constitutes acceptance of the revised Terms.
        </p>
      </Section>

      <Section heading="10. Contact Us">
        <p>
          Questions about these Terms? Contact us at{" "}
          <span className="text-[#38BDF8]">legal@ironclaw-security.com</span>.
        </p>
      </Section>
    </LegalLayout>
  );
};

export default Terms;
