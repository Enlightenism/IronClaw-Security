import { useState } from "react";

import ContactModal from "@/components/ContactModal";

const KNIGHT_LOGO_SRC = "/images/Golden%20Knight%20Logo128.png";

const ContactBubble = () => {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        data-testid="contact-bubble"
        aria-label="Contact IronClaw-Security"
        className="fixed bottom-5 right-5 z-40 flex flex-col items-center gap-1 rounded-2xl p-1 transition-transform duration-300 hover:scale-105 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FFD700]/50 sm:bottom-6 sm:right-6"
      >
        <img
          src={KNIGHT_LOGO_SRC}
          alt=""
          aria-hidden="true"
          className="contact-bubble-knight h-14 w-14 sm:h-16 sm:w-16"
        />
        <span className="metal-gold-text inline-block text-[11px] leading-none sm:text-xs">
          CONTACT
        </span>
      </button>
      <ContactModal open={open} onOpenChange={setOpen} />
    </>
  );
};

export default ContactBubble;
