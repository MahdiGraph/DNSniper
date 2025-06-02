import React from 'react';
import { createRoot } from 'react-dom/client';
import { CheckCircle, XCircle, AlertTriangle, Info, HelpCircle, X } from 'lucide-react';

// Modal component for alerts
const AlertModal = ({ 
  type = 'info', 
  title, 
  text, 
  showCancelButton = false,
  confirmButtonText = 'OK',
  cancelButtonText = 'Cancel',
  confirmButtonColor = '#007bff',
  onConfirm,
  onCancel,
  input = null,
  inputValue = '',
  inputPlaceholder = '',
  inputValidator = null,
  required = true
}) => {
  const [inputVal, setInputVal] = React.useState(inputValue);
  const [inputError, setInputError] = React.useState('');
  const [isProcessing, setIsProcessing] = React.useState(false);

  const getIcon = () => {
    switch (type) {
      case 'success': return <CheckCircle size={48} className="text-green-500" />;
      case 'error': return <XCircle size={48} className="text-red-500" />;
      case 'warning': return <AlertTriangle size={48} className="text-yellow-500" />;
      case 'question': return <HelpCircle size={48} className="text-blue-500" />;
      default: return <Info size={48} className="text-blue-500" />;
    }
  };

  const handleConfirm = async () => {
    if (isProcessing) return;
    
    if (input && inputValidator) {
      const error = inputValidator(inputVal);
      if (error) {
        setInputError(error);
        return;
      }
    }
    
    if (input && required && !inputVal.trim()) {
      setInputError('This field is required!');
      return;
    }

    setIsProcessing(true);
    
    try {
      await new Promise(resolve => setTimeout(resolve, 100)); // Small delay for UX
      onConfirm(input ? { isConfirmed: true, value: inputVal } : { isConfirmed: true });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCancel = () => {
    if (isProcessing) return;
    onCancel({ isConfirmed: false, isDismissed: true });
  };

  const handleKeyPress = (e) => {
    if (isProcessing) return;
    
    if (e.key === 'Enter' && !showCancelButton) {
      handleConfirm();
    } else if (e.key === 'Escape') {
      handleCancel();
    }
  };

  React.useEffect(() => {
    document.addEventListener('keydown', handleKeyPress);
    return () => document.removeEventListener('keydown', handleKeyPress);
  }, [inputVal, isProcessing]);

  return (
    <div className="modal-overlay" onClick={handleCancel}>
      <div className="modal custom-alert-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="alert-icon">
            {getIcon()}
          </div>
          <button className="modal-close" onClick={handleCancel} disabled={isProcessing}>
            <X size={16} />
          </button>
        </div>
        
        <div className="modal-body">
          <h3 className="alert-title">{title}</h3>
          {text && <p className="alert-text">{text}</p>}
          
          {input && (
            <div className="form-group">
              <input
                type={input}
                value={inputVal}
                onChange={(e) => {
                  setInputVal(e.target.value);
                  setInputError('');
                }}
                placeholder={inputPlaceholder}
                className={inputError ? 'error' : ''}
                autoFocus
                disabled={isProcessing}
              />
              {inputError && <div className="error-message">{inputError}</div>}
            </div>
          )}
        </div>
        
        <div className="modal-footer">
          {showCancelButton && (
            <button 
              type="button" 
              className="btn btn-secondary" 
              onClick={handleCancel}
              disabled={isProcessing}
            >
              {cancelButtonText}
            </button>
          )}
          <button 
            type="button" 
            className="btn btn-primary" 
            style={confirmButtonColor !== '#007bff' ? { backgroundColor: confirmButtonColor } : {}}
            onClick={handleConfirm}
            disabled={isProcessing}
          >
            {isProcessing ? 'Processing...' : confirmButtonText}
          </button>
        </div>
      </div>
    </div>
  );
};

// Loading modal component
const LoadingModal = ({ title, text }) => (
  <div className="modal-overlay">
    <div className="modal loading-modal" onClick={(e) => e.stopPropagation()}>
      <div className="modal-body">
        <div className="loading-spinner"></div>
        <h3>{title}</h3>
        {text && <p>{text}</p>}
      </div>
    </div>
  </div>
);

// Global state for managing modals
let currentModalRoot = null;
let currentModalContainer = null;

const createModal = (modalComponent) => {
  return new Promise((resolve) => {
    // Clean up any existing modal
    cleanup();

    // Create modal container
    currentModalContainer = document.createElement('div');
    currentModalContainer.className = 'custom-alert-container';
    document.body.appendChild(currentModalContainer);

    // Create React root
    currentModalRoot = createRoot(currentModalContainer);

    const handleResolve = (result) => {
      cleanup();
      resolve(result);
    };

    // Render modal
    currentModalRoot.render(
      React.cloneElement(modalComponent, {
        onConfirm: handleResolve,
        onCancel: handleResolve
      })
    );
  });
};

const cleanup = () => {
  if (currentModalRoot) {
    currentModalRoot.unmount();
    currentModalRoot = null;
  }
  if (currentModalContainer) {
    document.body.removeChild(currentModalContainer);
    currentModalContainer = null;
  }
};

// Public API functions that match the original alert API
export const showSuccess = (title, text = '', options = {}) => {
  return createModal(
    <AlertModal
      type="success"
      title={title}
      text={text}
      confirmButtonText="OK"
      {...options}
    />
  );
};

export const showError = (title, text = '', options = {}) => {
  return createModal(
    <AlertModal
      type="error"
      title={title}
      text={text}
      confirmButtonText="OK"
      {...options}
    />
  );
};

export const showWarning = (title, text = '', options = {}) => {
  return createModal(
    <AlertModal
      type="warning"
      title={title}
      text={text}
      confirmButtonText="OK"
      {...options}
    />
  );
};

export const showInfo = (title, text = '', options = {}) => {
  return createModal(
    <AlertModal
      type="info"
      title={title}
      text={text}
      confirmButtonText="OK"
      {...options}
    />
  );
};

export const showConfirm = (title, text = '', options = {}) => {
  return createModal(
    <AlertModal
      type="question"
      title={title}
      text={text}
      showCancelButton={true}
      confirmButtonText="Yes"
      cancelButtonText="Cancel"
      {...options}
    />
  );
};

export const showDeleteConfirm = (title, text = '', options = {}) => {
  return createModal(
    <AlertModal
      type="warning"
      title={title}
      text={text}
      showCancelButton={true}
      confirmButtonText="Delete"
      cancelButtonText="Cancel"
      confirmButtonColor="#ef4444"
      {...options}
    />
  );
};

export const showPrompt = (title, text = '', inputValue = '', options = {}) => {
  return createModal(
    <AlertModal
      type="question"
      title={title}
      text={text}
      input="text"
      inputValue={inputValue}
      showCancelButton={true}
      confirmButtonText="OK"
      cancelButtonText="Cancel"
      required={options.required !== false}
      {...options}
    />
  );
};

export const showLoading = (title = 'Loading...', text = '') => {
  // Clean up any existing modal
  cleanup();

  // Create modal container
  currentModalContainer = document.createElement('div');
  currentModalContainer.className = 'custom-alert-container';
  document.body.appendChild(currentModalContainer);

  // Create React root
  currentModalRoot = createRoot(currentModalContainer);

  // Render loading modal
  currentModalRoot.render(<LoadingModal title={title} text={text} />);

  // Return object with close method
  return {
    close: cleanup
  };
};

export const close = () => {
  cleanup();
};

export const showDangerousConfirm = (title, text, confirmText = 'CONFIRM') => {
  return createModal(
    <AlertModal
      type="warning"
      title={title}
      text={text}
      input="text"
      inputPlaceholder={`Type "${confirmText}" to confirm`}
      showCancelButton={true}
      confirmButtonText="Proceed"
      cancelButtonText="Cancel"
      confirmButtonColor="#ef4444"
      inputValidator={(value) => {
        if (value !== confirmText) {
          return `You must type "${confirmText}" exactly to confirm this action.`;
        }
      }}
    />
  );
};

// Utility function to show loading during async operations
export const showLoadingDuring = async (operation, loadingTitle = 'Processing...', loadingText = 'Please wait...') => {
  const loadingModal = showLoading(loadingTitle, loadingText);
  
  try {
    const result = await operation();
    loadingModal.close();
    return result;
  } catch (error) {
    loadingModal.close();
    throw error;
  }
};

// Default export for backward compatibility
const customAlert = {
  fire: (options) => {
    const { icon, title, text, showCancelButton, confirmButtonText, cancelButtonText, confirmButtonColor, input, inputValue, inputValidator, ...rest } = options;
    
    return createModal(
      <AlertModal
        type={icon}
        title={title}
        text={text}
        showCancelButton={showCancelButton}
        confirmButtonText={confirmButtonText}
        cancelButtonText={cancelButtonText}
        confirmButtonColor={confirmButtonColor}
        input={input}
        inputValue={inputValue}
        inputValidator={inputValidator}
        {...rest}
      />
    );
  }
};

export default customAlert; 