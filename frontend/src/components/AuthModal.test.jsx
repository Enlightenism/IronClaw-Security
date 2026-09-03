import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import AuthModal from "@/components/AuthModal";

jest.mock("@/hooks/useDebounce", () => ({
  useDebounce: (value) => value,
}));

const mockNavigate = jest.fn();
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useNavigate: () => mockNavigate,
}));

const mockAuthenticate = jest.fn();
const mockRegister = jest.fn();
jest.mock("@/context/AuthContext", () => ({
  useAuth: () => ({
    authenticate: mockAuthenticate,
    register: mockRegister,
  }),
}));

const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();
jest.mock("sonner", () => ({
  toast: {
    success: (...args) => mockToastSuccess(...args),
    error: (...args) => mockToastError(...args),
  },
}));

jest.mock("framer-motion", () => {
  const actual = jest.requireActual("framer-motion");
  return {
    ...actual,
    AnimatePresence: ({ children }) => <>{children}</>,
    motion: new Proxy(
      {},
      {
        get:
          (_, tag) =>
          ({ children, ...props }) => {
            const filteredProps = { ...props };
            delete filteredProps.initial;
            delete filteredProps.animate;
            delete filteredProps.exit;
            delete filteredProps.transition;
            delete filteredProps.whileHover;
            delete filteredProps.whileTap;

            const Tag = tag;
            return <Tag {...filteredProps}>{children}</Tag>;
          },
      },
    ),
  };
});

const renderModal = (props = {}) => {
  const defaults = {
    open: true,
    onClose: jest.fn(),
    initialMode: "signin",
  };

  return render(
    <MemoryRouter
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <AuthModal {...defaults} {...props} />
    </MemoryRouter>,
  );
};

const fillEmail = (value) =>
  fireEvent.change(screen.getByTestId("auth-email-input"), {
    target: { value },
  });

const fillPassword = (value) =>
  fireEvent.change(screen.getByTestId("auth-password-input"), {
    target: { value },
  });

const submitForm = () =>
  fireEvent.submit(screen.getByTestId("auth-submit-btn").closest("form"));

const submitBtn = () => screen.getByTestId("auth-submit-btn");

beforeEach(() => {
  jest.clearAllMocks();
});

describe("AuthModal", () => {
  describe("visibility", () => {
    it("renders when open is true", () => {
      renderModal({ open: true });
      expect(screen.getByTestId("auth-modal")).toBeInTheDocument();
    });

    it("renders nothing when open is false", () => {
      renderModal({ open: false });
      expect(screen.queryByTestId("auth-modal")).not.toBeInTheDocument();
    });
  });

  describe("initial mode", () => {
    it("shows Sign in submit button when initialMode is signin", () => {
      renderModal({ initialMode: "signin" });
      expect(submitBtn()).toHaveTextContent(/sign in/i);
    });

    it("shows Create account submit button when initialMode is signup", () => {
      renderModal({ initialMode: "signup" });
      expect(submitBtn()).toHaveTextContent(/create account/i);
    });
  });

  describe("mode switching", () => {
    it("switches from signin to signup when Create an account is clicked", async () => {
      renderModal({ initialMode: "signin" });
      await userEvent.click(screen.getByTestId("switch-to-signup"));
      expect(submitBtn()).toHaveTextContent(/create account/i);
    });

    it("switches from signup back to signin when Sign in is clicked", async () => {
      renderModal({ initialMode: "signup" });
      await userEvent.click(screen.getByTestId("switch-to-signin"));
      expect(submitBtn()).toHaveTextContent(/sign in/i);
    });
  });

  describe("form inputs", () => {
    it("updates email field on change", () => {
      renderModal();
      fillEmail("operator@ironclaw.io");
      expect(screen.getByTestId("auth-email-input").value).toBe(
        "operator@ironclaw.io",
      );
    });

    it("updates password field on change", () => {
      renderModal();
      fillPassword("SecurePass123!");
      expect(screen.getByTestId("auth-password-input").value).toBe(
        "SecurePass123!",
      );
    });
  });

  describe("email validation", () => {
    it("shows validation error when email is missing", async () => {
      renderModal({ initialMode: "signin" });
      fillPassword("SecurePass123!");
      submitForm();

      await waitFor(() => {
        expect(screen.getByTestId("auth-email-status")).toHaveTextContent(
          "Email is required.",
        );
      });

      expect(mockAuthenticate).not.toHaveBeenCalled();
    });

    it("shows validation error when email format is invalid", async () => {
      renderModal({ initialMode: "signin" });
      fillEmail("not-an-email");
      fillPassword("SecurePass123!");
      submitForm();

      await waitFor(() => {
        expect(screen.getByTestId("auth-email-status")).toHaveTextContent(
          "Enter a valid email address.",
        );
      });

      expect(mockAuthenticate).not.toHaveBeenCalled();
    });

    it("shows success status when email is valid after blur", async () => {
      renderModal({ initialMode: "signin" });
      const input = screen.getByTestId("auth-email-input");
      fillEmail("operator@ironclaw.io");
      fireEvent.blur(input);

      await waitFor(() => {
        expect(screen.getByTestId("auth-email-status")).toHaveTextContent(
          "Email looks good.",
        );
      });
    });
  });

  describe("sign in submission", () => {
    it("calls authenticate with trimmed email and password on signin submit", async () => {
      mockAuthenticate.mockResolvedValueOnce({
        user: { id: "user-1", email: "operator@ironclaw.io" },
        session: { access_token: "token-123" },
      });

      renderModal({ initialMode: "signin" });
      fillEmail("  operator@ironclaw.io  ");
      fillPassword("SecurePass123!");
      submitForm();

      await waitFor(() => {
        expect(mockAuthenticate).toHaveBeenCalledWith(
          "operator@ironclaw.io",
          "SecurePass123!",
        );
      });
    });

    it("shows success toast and navigates to dashboard on successful signin", async () => {
      mockAuthenticate.mockResolvedValueOnce({
        user: { id: "user-1", email: "operator@ironclaw.io" },
        session: { access_token: "token-123" },
      });

      renderModal({ initialMode: "signin" });
      fillEmail("operator@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(mockToastSuccess).toHaveBeenCalledWith(
          "Welcome back, operator.",
        );
        expect(mockNavigate).toHaveBeenCalledWith("/dashboard");
      });
    });

    it("shows error toast when signin returns no active session", async () => {
      mockAuthenticate.mockResolvedValueOnce({});

      renderModal({ initialMode: "signin" });
      fillEmail("operator@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(mockToastError).toHaveBeenCalledWith(
          "Authentication succeeded without an active session.",
        );
      });

      expect(mockNavigate).not.toHaveBeenCalled();
      expect(mockToastSuccess).not.toHaveBeenCalled();
    });

    it("shows error toast when signin fails", async () => {
      mockAuthenticate.mockRejectedValueOnce(new Error("Invalid credentials"));
      renderModal({ initialMode: "signin" });
      fillEmail("bad@bad.com");
      fillPassword("wrong");
      submitForm();

      await waitFor(() => {
        expect(mockToastError).toHaveBeenCalledWith("Invalid credentials");
      });
    });
  });

  describe("sign up submission", () => {
    it("calls register with trimmed email and password on signup submit", async () => {
      mockRegister.mockResolvedValueOnce({
        user: { id: "user-2", email: "new@ironclaw.io" },
        session: { access_token: "token-456" },
      });

      renderModal({ initialMode: "signup" });
      fillEmail("  new@ironclaw.io  ");
      fillPassword("NewPass123!");
      submitForm();

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith(
          "new@ironclaw.io",
          "NewPass123!",
        );
      });
    });

    it("shows success toast and navigates to dashboard on successful signup", async () => {
      mockRegister.mockResolvedValueOnce({
        user: { id: "user-2", email: "new@ironclaw.io" },
        session: { access_token: "token-456" },
      });

      renderModal({ initialMode: "signup" });
      fillEmail("new@ironclaw.io");
      fillPassword("NewPass123!");
      submitForm();

      await waitFor(() => {
        expect(mockToastSuccess).toHaveBeenCalledWith(
          "Account created. Defenses online.",
        );
        expect(mockNavigate).toHaveBeenCalledWith("/dashboard");
      });
    });

    it("shows error toast when signup returns no active session", async () => {
      mockRegister.mockResolvedValueOnce({});

      renderModal({ initialMode: "signup" });
      fillEmail("new@ironclaw.io");
      fillPassword("NewPass123!");
      submitForm();

      await waitFor(() => {
        expect(mockToastError).toHaveBeenCalledWith(
          "Authentication succeeded without an active session.",
        );
      });

      expect(mockNavigate).not.toHaveBeenCalled();
      expect(mockToastSuccess).not.toHaveBeenCalled();
    });

    it("shows error toast when signup fails", async () => {
      mockRegister.mockRejectedValueOnce(new Error("Email already in use"));
      renderModal({ initialMode: "signup" });
      fillEmail("dup@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(mockToastError).toHaveBeenCalledWith("Email already in use");
      });
    });
  });

  describe("loading state", () => {
    it("disables the submit button while loading", async () => {
      mockAuthenticate.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 500)),
      );

      renderModal({ initialMode: "signin" });
      fillEmail("operator@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(submitBtn()).toBeDisabled();
      });
    });
  });

  describe("onClose", () => {
    it("calls onClose after successful signin", async () => {
      const onClose = jest.fn();
      mockAuthenticate.mockResolvedValueOnce({
        user: { id: "user-1", email: "operator@ironclaw.io" },
        session: { access_token: "token-123" },
      });

      renderModal({ onClose, initialMode: "signin" });
      fillEmail("operator@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(onClose).toHaveBeenCalled();
      });
    });

    it("does not call onClose when signin returns no active session", async () => {
      const onClose = jest.fn();
      mockAuthenticate.mockResolvedValueOnce({});

      renderModal({ onClose, initialMode: "signin" });
      fillEmail("operator@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(mockToastError).toHaveBeenCalledWith(
          "Authentication succeeded without an active session.",
        );
      });

      expect(onClose).not.toHaveBeenCalled();
    });
  });

  describe("generic error fallback", () => {
    it("shows fallback message when error has no message property", async () => {
      mockAuthenticate.mockRejectedValueOnce({});
      renderModal({ initialMode: "signin" });
      fillEmail("operator@ironclaw.io");
      fillPassword("pass123");
      submitForm();

      await waitFor(() => {
        expect(mockToastError).toHaveBeenCalledWith(
          "Something went wrong. Try again.",
        );
      });
    });
  });
});
