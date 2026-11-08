import { useState } from "react";
import { Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { contact } from "@/lib/api";
import { cn } from "@/lib/utils";

export const CONTACT_EMAIL = "Enlightenism333@gmail.com";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const EMPTY_FORM = { name: "", email: "", message: "" };
const GENERIC_ERROR = "Message could not be sent. Please try again.";
const KNIGHT_LOGO_SRC = "/images/Golden%20Knight%20Logo128.png";
const FIELD_CLASS =
  "border-white/15 bg-white/5 text-white placeholder:text-white/40 focus-visible:border-[#FFD700]/60 focus-visible:ring-2 focus-visible:ring-[#FFD700]/25";
const LABEL_CLASS =
  "text-[11px] font-semibold uppercase tracking-[0.18em] text-[#FFD700]/80";

const getErrorMessage = (error) => {
  const apiMessage =
    error?.response?.data?.message || error?.response?.data?.detail;
  return typeof apiMessage === "string" && apiMessage
    ? apiMessage
    : GENERIC_ERROR;
};

const ContactModal = ({ open, onOpenChange }) => {
  const [form, setForm] = useState(EMPTY_FORM);
  const [errors, setErrors] = useState({});
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [submitError, setSubmitError] = useState("");

  const handleChange = (field) => (event) => {
    setForm((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleOpenChange = (nextOpen) => {
    if (!nextOpen) {
      setSent(false);
      setSubmitError("");
      setErrors({});
    }
    onOpenChange(nextOpen);
  };

  const validate = () => {
    const nextErrors = {};
    if (!form.name.trim()) {
      nextErrors.name = "Name is required.";
    }
    if (!EMAIL_REGEX.test(form.email.trim())) {
      nextErrors.email = "Enter a valid email address.";
    }
    if (!form.message.trim()) {
      nextErrors.message = "Please describe the issue you are having.";
    }
    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (sending || !validate()) {
      return;
    }

    setSending(true);
    setSent(false);
    setSubmitError("");
    try {
      await contact.send({
        name: form.name.trim(),
        email: form.email.trim(),
        message: form.message.trim(),
      });
      setSent(true);
      setForm(EMPTY_FORM);
    } catch (error) {
      setSubmitError(getErrorMessage(error));
    } finally {
      setSending(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="overflow-hidden rounded-2xl border-[#FFD700]/25 bg-[#0B0B0F]/95 p-7 text-white shadow-[0_0_60px_rgba(255,215,0,0.12)] backdrop-blur-xl sm:max-w-lg sm:rounded-2xl">
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#FFD700] to-transparent"
        />
        <DialogHeader className="flex-row items-center gap-4 space-y-0 pr-8 text-left">
          <div className="metal-gold-icon flex h-14 w-14 shrink-0 items-center justify-center rounded-xl p-2">
            <img
              src={KNIGHT_LOGO_SRC}
              alt=""
              aria-hidden="true"
              className="h-full w-full object-contain"
            />
          </div>
          <div className="grid gap-1">
            <DialogTitle className="font-tech text-2xl font-semibold tracking-tight text-white">
              Contact <span className="metal-gold-text">IronClaw-Security</span>
            </DialogTitle>
            <DialogDescription className="text-[#BFC1C2]">
              Describe the issue you are having and we will get back to you at
              the email you provide. This is a basic email contact form. For
              security reasons we do not allow other AI APIs on our platform, so
              our AI brain is fully local with no connection to any other AI
              source.
            </DialogDescription>
          </div>
        </DialogHeader>

        <form
          onSubmit={handleSubmit}
          noValidate
          className="grid gap-4"
          data-testid="contact-form"
        >
          <div className="grid gap-1.5">
            <label htmlFor="contact-name" className={LABEL_CLASS}>
              Name
            </label>
            <Input
              id="contact-name"
              value={form.name}
              onChange={handleChange("name")}
              maxLength={120}
              autoComplete="name"
              aria-invalid={Boolean(errors.name)}
              className={cn(
                FIELD_CLASS,
                "h-11",
                errors.name && "border-red-400/60",
              )}
            />
            {errors.name && (
              <p className="text-xs text-red-400">{errors.name}</p>
            )}
          </div>

          <div className="grid gap-1.5">
            <label htmlFor="contact-email" className={LABEL_CLASS}>
              Email
            </label>
            <Input
              id="contact-email"
              type="email"
              value={form.email}
              onChange={handleChange("email")}
              maxLength={254}
              autoComplete="email"
              aria-invalid={Boolean(errors.email)}
              className={cn(
                FIELD_CLASS,
                "h-11",
                errors.email && "border-red-400/60",
              )}
            />
            {errors.email && (
              <p className="text-xs text-red-400">{errors.email}</p>
            )}
          </div>

          <div className="grid gap-1.5">
            <label htmlFor="contact-message" className={LABEL_CLASS}>
              Issue
            </label>
            <Textarea
              id="contact-message"
              value={form.message}
              onChange={handleChange("message")}
              maxLength={5000}
              rows={5}
              aria-invalid={Boolean(errors.message)}
              className={cn(FIELD_CLASS, errors.message && "border-red-400/60")}
            />
            {errors.message && (
              <p className="text-xs text-red-400">{errors.message}</p>
            )}
          </div>

          {submitError && (
            <p
              role="alert"
              className="rounded-lg border border-red-400/30 bg-red-400/10 px-3 py-2 text-xs text-red-300"
            >
              {submitError}
            </p>
          )}
          {sent && (
            <p
              role="status"
              className="rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-xs text-emerald-300"
            >
              Thank you. Your message has been sent.
            </p>
          )}

          <Button
            type="submit"
            disabled={sending}
            className="h-11 w-full border border-[#FFD700]/40 bg-gradient-to-r from-[#fff6c2] via-[#ffd700] to-[#c9a84c] font-semibold text-black shadow-[0_8px_24px_rgba(255,215,0,0.25)] transition hover:brightness-110 hover:shadow-[0_12px_32px_rgba(255,215,0,0.4)]"
          >
            {sending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {sending ? "Sending..." : "Submit"}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default ContactModal;
