import LegalLayout, { Section } from "@/components/LegalLayout";

const Terms = () => {
  return (
    <LegalLayout title="Terms of Service" updated="June 1, 2026" testid="terms-page">
      <p className="text-sm leading-relaxed">
        These Terms of Service ("Terms") form a legally binding agreement between
        you and IronClaw-Security ("IronClaw-Security", "we", "us", or "our") and
        govern your access to and use of our platform, website, APIs, and related
        services (collectively, the "Service"). By creating an account, accessing,
        or using the Service, you agree to be bound by these Terms. If you do not
        agree, you must not access or use the Service.
      </p>

      <Section heading="1. Eligibility & Accounts">
        <p>
          You must be at least 18 years old and legally capable of forming a
          binding contract to use the Service. You are solely responsible for
          maintaining the confidentiality of your account credentials and install
          tokens, and for all activity that occurs under your account. You agree
          to provide accurate information and to notify us promptly of any
          unauthorized use.
        </p>
      </Section>

      <Section heading="2. The Service & No Guarantee">
        <p>
          IronClaw-Security provides an enforcement layer that inspects and
          governs AI agent activity, including prompt-injection defense, action
          guarding, policy enforcement, sandboxed execution, and auditing. The
          Service is a risk-reduction tool only.{" "}
          <strong className="text-white">
            IronClaw-Security does not guarantee that all threats, attacks,
            vulnerabilities, data leaks, or malicious actions will be detected,
            prevented, or mitigated.
          </strong>{" "}
          You remain solely responsible for the design, operation, and security
          of your own systems, agents, and data.
        </p>
      </Section>

      <Section heading="3. Units, Billing & Payments">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            The Service operates on a prepaid, usage-based "unit" model. Units are
            consumed as your agents are protected.
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
            Except where required by applicable law, all unit purchases are final
            and non-refundable. Purchased units do not expire while your account
            remains active.
          </li>
          <li>We may change pricing prospectively at any time.</li>
        </ul>
      </Section>

      <Section heading="4. Acceptable Use">
        <p>You agree not to:</p>
        <ul className="list-disc space-y-1 pl-5">
          <li>Use the Service for any unlawful, harmful, or malicious purpose;</li>
          <li>
            Attempt to bypass, disable, probe, or interfere with the Service's
            security or enforcement layers;
          </li>
          <li>
            Access another organization's data or attempt to break tenant
            isolation;
          </li>
          <li>
            Reverse engineer, decompile, scrape, or resell the Service without
            authorization; or
          </li>
          <li>Introduce malware or overload, disrupt, or impair the Service.</li>
        </ul>
        <p>
          We may suspend or terminate access immediately for any actual or
          suspected violation.
        </p>
      </Section>

      <Section heading="5. Intellectual Property">
        <p>
          The Service, including all software, design, trademarks, and content, is
          owned by IronClaw-Security and its licensors and is protected by
          intellectual property laws. We grant you a limited, non-exclusive,
          non-transferable, revocable license to use the Service in accordance
          with these Terms. You retain ownership of data you submit and grant us a
          worldwide license to host, process, and use it as necessary to provide,
          secure, and improve the Service.
        </p>
      </Section>

      <Section heading="6. Disclaimer of Warranties">
        <p>
          THE SERVICE AND ALL OUTPUTS, VERDICTS, AND CONTENT ARE PROVIDED "AS IS"
          AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS,
          IMPLIED, STATUTORY, OR OTHERWISE, INCLUDING ANY IMPLIED WARRANTIES OF
          MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, ACCURACY, AND
          NON-INFRINGEMENT. WE DO NOT WARRANT THAT THE SERVICE WILL BE
          UNINTERRUPTED, TIMELY, SECURE, ERROR-FREE, OR THAT IT WILL DETECT OR
          PREVENT ALL THREATS. YOU USE THE SERVICE ENTIRELY AT YOUR OWN RISK.
        </p>
      </Section>

      <Section heading="7. Limitation of Liability">
        <p>
          TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IRONCLAW-SECURITY AND
          ITS OFFICERS, DIRECTORS, EMPLOYEES, CONTRACTORS, AGENTS, LICENSORS, AND
          AFFILIATES SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
          CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, OR FOR ANY LOSS OF
          PROFITS, REVENUES, DATA, GOODWILL, BUSINESS, OR SECURITY BREACH,
          HOWEVER CAUSED AND UNDER ANY THEORY OF LIABILITY, EVEN IF ADVISED OF THE
          POSSIBILITY OF SUCH DAMAGES. IN NO EVENT SHALL THE AGGREGATE LIABILITY OF
          IRONCLAW-SECURITY EXCEED THE GREATER OF (A) THE TOTAL AMOUNTS YOU PAID TO
          IRONCLAW-SECURITY IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING
          RISE TO THE CLAIM, OR (B) ONE HUNDRED U.S. DOLLARS (USD $100). SOME
          JURISDICTIONS DO NOT ALLOW CERTAIN LIMITATIONS, SO SOME OF THE ABOVE MAY
          NOT APPLY TO YOU.
        </p>
      </Section>

      <Section heading="8. Indemnification">
        <p>
          You agree to defend, indemnify, and hold harmless IronClaw-Security and
          its officers, directors, employees, contractors, agents, licensors, and
          affiliates from and against any and all claims, damages, obligations,
          losses, liabilities, costs, and expenses (including reasonable
          attorneys' fees) arising from or related to: (a) your use of the
          Service; (b) your data or systems; (c) your violation of these Terms or
          any applicable law; or (d) your infringement of any third-party right.
        </p>
      </Section>

      <Section heading="9. Termination">
        <p>
          We may suspend or terminate your access to the Service at any time, with
          or without cause or notice. Upon termination, your right to use the
          Service ceases immediately. Sections concerning intellectual property,
          disclaimers, limitation of liability, indemnification, and dispute
          resolution survive termination.
        </p>
      </Section>

      <Section heading="10. Changes to These Terms">
        <p>
          We may revise these Terms at any time, in our sole discretion. Material
          changes will be reflected by updating the "Last updated" date above.
          Your continued use of the Service after any change constitutes
          acceptance of the revised Terms.
        </p>
      </Section>

      <Section heading="11. Governing Law, Binding Arbitration & Class Action Waiver">
        <p>
          These Terms and any dispute arising out of or relating to them or the
          Service shall be governed by the laws of the State of Delaware, USA,
          without regard to conflict-of-laws principles. Any dispute, claim, or
          controversy shall be resolved exclusively through final and binding
          individual arbitration administered under the rules of a recognized
          arbitration body, and not in court, except that either party may seek
          injunctive or equitable relief for intellectual-property or
          unauthorized-access matters.{" "}
          <strong className="text-white">
            YOU AND IRONCLAW-SECURITY EACH WAIVE ANY RIGHT TO A JURY TRIAL AND ANY
            RIGHT TO BRING OR PARTICIPATE IN A CLASS, COLLECTIVE, CONSOLIDATED, OR
            REPRESENTATIVE ACTION.
          </strong>{" "}
          Any claim must be filed within one (1) year after the claim arises, or
          it is permanently and forever barred.
        </p>
      </Section>

      <Section heading="12. Force Majeure">
        <p>
          IronClaw-Security shall not be liable for any delay or failure to
          perform resulting from causes beyond its reasonable control, including
          acts of God, war, terrorism, cyberattacks, internet or utility
          failures, governmental action, or other force majeure events.
        </p>
      </Section>

      <Section heading="13. Severability & Entire Agreement">
        <p>
          If any provision of these Terms is held invalid or unenforceable, that
          provision shall be limited or eliminated to the minimum extent necessary
          and the remaining provisions shall remain in full force and effect. Our
          failure to enforce any right or provision is not a waiver of that right
          or provision. These Terms, together with our Privacy Policy, constitute
          the entire agreement between you and IronClaw-Security regarding the
          Service and supersede all prior agreements.
        </p>
      </Section>

      <Section heading="14. Full Release & Waiver of Legal Action">
        <p>
          By using the Service, you knowingly and voluntarily release, waive, and
          forever discharge IronClaw-Security and its officers, directors,
          employees, contractors, agents, licensors, and affiliates from any and
          all claims, demands, causes of action, damages, and liabilities of every
          kind and nature, whether known or unknown, arising out of or in any way
          connected with your use of the Service, including any failure to detect
          or prevent a threat, any security incident, data loss, or downtime, to
          the fullest extent permitted by applicable law. You agree that
          IronClaw-Security shall bear no liability whatsoever beyond the limits
          expressly stated in these Terms, and you irrevocably agree not to bring
          any claim or legal action against IronClaw-Security except as expressly
          permitted herein.
        </p>
      </Section>

      <Section heading="15. Contact Us">
        <p>
          Questions about these Terms? Contact us at{" "}
          <span className="text-[#38BDF8]">legal@ironclaw-security.com</span>.
        </p>
      </Section>
    </LegalLayout>
  );
};

export default Terms;
