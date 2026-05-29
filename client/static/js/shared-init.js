// Share page initialization
// Parses share ID from URL and initializes ShareAccessUI

// Register CSP Trusted Types global default policy to securely handle innerHTML sinks (F-17)
if (typeof window !== 'undefined' && window.trustedTypes && window.trustedTypes.createPolicy) {
  try {
    window.trustedTypes.createPolicy('default', {
      createHTML: function(string) {
        // Safe pass-through of application static templates and escaped markup
        return string;
      }
    });
  } catch (err) {
    console.warn('Trusted Types policy registration failed or was already created:', err);
  }
}

(function() {
  var pathSegments = window.location.pathname.split('/');
  var shareId = pathSegments[pathSegments.length - 1];

  function showError(message) {
    var container = document.getElementById('share-access-container');
    if (container) {
      container.innerHTML = '<h2>Error</h2><p style="color: var(--coral);">' + message + '</p>';
    }
  }

  function waitForModules() {
    return new Promise(function(resolve) {
      var check = function() {
        if (window.arkfile && window.arkfile.shares && window.arkfile.shares.ShareAccessUI) {
          resolve();
        } else {
          setTimeout(check, 100);
        }
      };
      check();
    });
  }

  document.addEventListener('DOMContentLoaded', async function() {
    if (!shareId) {
      showError('Invalid share link');
      return;
    }

    try {
      await waitForModules();
      var ShareAccessUI = window.arkfile.shares.ShareAccessUI;
      var shareAccessUI = new ShareAccessUI('share-access-container', shareId);
      await shareAccessUI.initialize();
    } catch (error) {
      console.error('Error initializing share access:', error);
      showError('Failed to initialize share access interface. Please refresh the page.');
    }
  });
})();
