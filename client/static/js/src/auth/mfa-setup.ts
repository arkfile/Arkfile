/**
 * Unified MFA enrollment entry point after OPAQUE registration or login resume.
 */

import { buildTOTPSetupFlowData, handleTOTPSetupFlow } from './totp-setup.js';
import { handleWebAuthnSetupFlow } from './webauthn.js';
import {
  showMFAMethodPicker,
  type MFASetupFlowData,
  type MFAMethod,
} from './mfa-method.js';

export type { MFASetupFlowData, MFAMethod };

function totpSetupFromFlow(data: MFASetupFlowData) {
  return buildTOTPSetupFlowData({
    tempToken: data.tempToken,
    username: data.username,
    addSecondFactor: data.addSecondFactor,
  });
}

function methodPickerOptions(data: MFASetupFlowData): { addSecondFactor?: boolean } {
  return data.addSecondFactor === true ? { addSecondFactor: true } : {};
}

/**
 * Begin MFA enrollment. Shows a method picker unless the server or caller
 * already specified totp or webauthn (e.g. pending enrollment resume).
 */
export function handleMFASetupFlow(data: MFASetupFlowData): void {
  const method = (data.mfaMethod || '').trim() as MFAMethod | '';

  if (method === 'totp') {
    handleTOTPSetupFlow(totpSetupFromFlow(data));
    return;
  }

  if (method === 'webauthn') {
    handleWebAuthnSetupFlow(data);
    return;
  }

  showMFAMethodPicker((selected) => {
    if (selected === 'totp') {
      handleTOTPSetupFlow(totpSetupFromFlow(data));
    } else {
      handleWebAuthnSetupFlow({ ...data, mfaMethod: 'webauthn' });
    }
  }, methodPickerOptions(data));
}
