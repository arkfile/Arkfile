/**
 * TypeScript definitions for DOM utilities and UI components
 */

// Modal types
interface ModalButton {
  text: string;
  action: () => void | Promise<void>;
  variant?: 'primary' | 'secondary' | 'danger' | 'success';
  disabled?: boolean;
  loading?: boolean;
}

interface ModalOptions {
  title: string;
  message: string;
  buttons?: ModalButton[];
  allowClose?: boolean;
  className?: string;
  size?: 'small' | 'medium' | 'large';
}

interface ConfirmModalOptions {
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: 'danger' | 'warning' | 'info';
  onConfirm: () => void | Promise<void>;
  onCancel?: () => void;
}

// Progress indicator types
interface ProgressOptions {
  title: string;
  message?: string;
  percentage?: number;
  indeterminate?: boolean;
  allowCancel?: boolean;
  onCancel?: () => void;
}

interface ProgressState {
  title: string;
  message?: string;
  percentage: number;
  stage: string;
  speed?: number;
  remainingTime?: number;
  error?: string;
}

// Toast/notification types
interface ToastOptions {
  message: string;
  type?: 'success' | 'error' | 'warning' | 'info';
  duration?: number; // milliseconds, 0 for permanent
  actions?: Array<{
    text: string;
    action: () => void;
  }>;
}

// Form validation types
interface FormFieldValidation {
  element: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
  rules: ValidationRule[];
  errorContainer?: HTMLElement;
}

interface ValidationRule {
  type: 'required' | 'email' | 'minLength' | 'maxLength' | 'pattern' | 'custom' | 'password' | 'confirmation';
  value?: any;
  message: string;
  validator?: (value: string, element: HTMLElement) => boolean | Promise<boolean>;
}

interface ValidationResult {
  valid: boolean;
  errors: Array<{
    field: string;
    message: string;
  }>;
}

// File input types
interface FileInputOptions {
  accept?: string;
  multiple?: boolean;
  maxSize?: number; // in bytes
  onSelect: (files: FileList) => void;
  onError?: (error: string) => void;
}

interface DragDropOptions {
  element: HTMLElement;
  accept?: string;
  multiple?: boolean;
  maxSize?: number;
  onDrop: (files: FileList) => void;
  onDragEnter?: (event: DragEvent) => void;
  onDragLeave?: (event: DragEvent) => void;
  onError?: (error: string) => void;
}

// Password strength indicator types
interface PasswordStrengthOptions {
  input: HTMLInputElement;
  container: HTMLElement;
  showRequirements?: boolean;
  showStrengthMeter?: boolean;
  realTime?: boolean;
}

interface PasswordRequirement {
  text: string;
  test: (password: string) => boolean;
  weight: number; // contribution to overall strength score
}

// Table/list types
interface TableColumn<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  formatter?: (value: any, row: T) => string | HTMLElement;
  className?: string;
}

interface TableOptions<T> {
  data: T[];
  columns: TableColumn<T>[];
  container: HTMLElement;
  sortable?: boolean;
  pagination?: {
    pageSize: number;
    showControls: boolean;
  };
  onRowClick?: (row: T, event: MouseEvent) => void;
  onSort?: (column: keyof T, direction: 'asc' | 'desc') => void;
}

// Event handler types
interface KeyboardShortcut {
  key: string;
  ctrlKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  metaKey?: boolean;
  handler: (event: KeyboardEvent) => void;
  description?: string;
}

interface ContextMenuOption {
  label: string;
  action: () => void;
  icon?: string;
  disabled?: boolean;
  separator?: boolean;
}

interface ContextMenuOptions {
  items: ContextMenuOption[];
  target: HTMLElement;
  event: MouseEvent;
}

// Animation types
interface AnimationOptions {
  duration?: number;
  easing?: 'linear' | 'ease' | 'ease-in' | 'ease-out' | 'ease-in-out';
  onComplete?: () => void;
}

interface SlideOptions extends AnimationOptions {
  direction?: 'up' | 'down' | 'left' | 'right';
}

interface FadeOptions extends AnimationOptions {
  startOpacity?: number;
  endOpacity?: number;
}

// Theme types
interface Theme {
  name: string;
  colors: {
    primary: string;
    secondary: string;
    success: string;
    warning: string;
    error: string;
    info: string;
    background: string;
    surface: string;
    text: string;
    textSecondary: string;
    border: string;
  };
  fonts: {
    primary: string;
    mono: string;
  };
  spacing: {
    xs: string;
    sm: string;
    md: string;
    lg: string;
    xl: string;
  };
  breakpoints: {
    mobile: string;
    tablet: string;
    desktop: string;
  };
}

// Utility types for DOM manipulation
interface ElementPosition {
  top: number;
  left: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
}

interface ScrollOptions {
  behavior?: ScrollBehavior;
  block?: ScrollLogicalPosition;
  inline?: ScrollLogicalPosition;
}

// Event listener management
interface EventListenerConfig {
  element: HTMLElement | Window | Document;
  event: string;
  handler: EventListener;
  options?: boolean | AddEventListenerOptions;
}

// Storage types
interface StorageItem<T = any> {
  key: string;
  value: T;
  expires?: number; // timestamp
  encrypted?: boolean;
}

interface StorageOptions {
  namespace?: string;
  encrypt?: boolean;
  compression?: boolean;
}

// Export all types
export type {
  ModalButton,
  ModalOptions,
  ConfirmModalOptions,
  ProgressOptions,
  ProgressState,
  ToastOptions,
  FormFieldValidation,
  ValidationRule,
  ValidationResult,
  FileInputOptions,
  DragDropOptions,
  PasswordStrengthOptions,
  PasswordRequirement,
  TableColumn,
  TableOptions,
  KeyboardShortcut,
  ContextMenuOption,
  ContextMenuOptions,
  AnimationOptions,
  SlideOptions,
  FadeOptions,
  Theme,
  ElementPosition,
  ScrollOptions,
  EventListenerConfig,
  StorageItem,
  StorageOptions
};
