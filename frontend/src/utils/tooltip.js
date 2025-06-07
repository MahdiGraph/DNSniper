// Tooltip utility for handling dynamic tooltips with proper positioning

class TooltipManager {
  constructor() {
    this.activeTooltip = null;
    this.showDelay = 300;
    this.hideDelay = 100;
    this.showTimeout = null;
    this.hideTimeout = null;
  }

  // Show tooltip for an element
  showTooltip(element, content) {
    if (!content || content.trim() === '') return;

    // Clear any pending hide timeout
    if (this.hideTimeout) {
      clearTimeout(this.hideTimeout);
      this.hideTimeout = null;
    }

    // Set a slight delay before showing
    this.showTimeout = setTimeout(() => {
      this.createTooltip(element, content);
    }, this.showDelay);
  }

  // Hide tooltip
  hideTooltip() {
    // Clear any pending show timeout
    if (this.showTimeout) {
      clearTimeout(this.showTimeout);
      this.showTimeout = null;
    }

    // Set a slight delay before hiding to prevent flickering
    this.hideTimeout = setTimeout(() => {
      this.removeTooltip();
    }, this.hideDelay);
  }

  // Create and position tooltip
  createTooltip(element, content) {
    // Remove existing tooltip
    this.removeTooltip();

    // Create tooltip element
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = content;
    document.body.appendChild(tooltip);

    // Calculate position
    const elementRect = element.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    // Calculate initial position (below element, centered)
    let left = elementRect.left + (elementRect.width / 2) - (tooltipRect.width / 2);
    let top = elementRect.bottom + 8;
    let arrowClass = '';

    // Adjust horizontal position if tooltip goes off screen
    if (left < 10) {
      left = 10;
    } else if (left + tooltipRect.width > viewportWidth - 10) {
      left = viewportWidth - tooltipRect.width - 10;
    }

    // Check if tooltip would go below viewport
    if (top + tooltipRect.height > viewportHeight - 10) {
      // Position above element instead
      top = elementRect.top - tooltipRect.height - 8;
      arrowClass = 'tooltip-top';
    }

    // Apply position with fixed positioning
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
    
    if (arrowClass) {
      tooltip.classList.add(arrowClass);
    }

    // Show tooltip with animation
    requestAnimationFrame(() => {
      tooltip.classList.add('show');
    });

    this.activeTooltip = tooltip;
  }

  // Remove tooltip
  removeTooltip() {
    if (this.activeTooltip) {
      this.activeTooltip.remove();
      this.activeTooltip = null;
    }
  }

  // Cleanup method
  cleanup() {
    if (this.showTimeout) {
      clearTimeout(this.showTimeout);
      this.showTimeout = null;
    }
    if (this.hideTimeout) {
      clearTimeout(this.hideTimeout);
      this.hideTimeout = null;
    }
    this.removeTooltip();
  }
}

// Create a singleton instance
const tooltipManager = new TooltipManager();

// Utility functions to be used in components
export const showTooltip = (element, content) => {
  tooltipManager.showTooltip(element, content);
};

export const hideTooltip = () => {
  tooltipManager.hideTooltip();
};

export const cleanupTooltips = () => {
  tooltipManager.cleanup();
};

// Hook for React components to easily add tooltip functionality
export const useTooltipHandlers = () => {
  const handleMouseEnter = (event) => {
    const element = event.currentTarget;
    const content = element.getAttribute('data-tooltip');
    if (content && element.classList.contains('has-tooltip')) {
      showTooltip(element, content);
    }
  };

  const handleMouseLeave = () => {
    hideTooltip();
  };

  return {
    onMouseEnter: handleMouseEnter,
    onMouseLeave: handleMouseLeave
  };
};

export default tooltipManager; 