import React from 'react';

const Button = ({
  children,
  variant = 'primary',
  className = '',
  disabled = false,
  type = 'button',
  size = 'default',
  loading = false,
  icon,
  glow = false,
  style,
  ...props
}) => {
  // Base styles with enhanced aesthetics
  const baseStyles = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.625rem',
    fontWeight: 600,
    fontFamily: 'inherit',
    borderRadius: '14px',
    border: 'none',
    cursor: disabled ? 'not-allowed' : loading ? 'wait' : 'pointer',
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    position: 'relative',
    overflow: 'hidden',
    outline: 'none',
    textDecoration: 'none',
    opacity: disabled ? 0.5 : 1,
    transform: 'translateY(0)',
    letterSpacing: '0.01em',
    whiteSpace: 'nowrap',
  };

  // Size variations with refined proportions
  const sizeStyles = {
    xs: {
      padding: '0.375rem 0.75rem',
      fontSize: '0.75rem',
      borderRadius: '10px',
    },
    sm: {
      padding: '0.5rem 1rem',
      fontSize: '0.8125rem',
      borderRadius: '12px',
    },
    default: {
      padding: '0.8125rem 1.5rem',
      fontSize: '0.9375rem',
      borderRadius: '14px',
    },
    lg: {
      padding: '1rem 2rem',
      fontSize: '1rem',
      borderRadius: '16px',
    },
    xl: {
      padding: '1.125rem 2.5rem',
      fontSize: '1.0625rem',
      borderRadius: '18px',
    },
  };

  // Enhanced variant styles with premium gradients
  const variantStyles = {
    primary: {
      background: 'linear-gradient(135deg, #8b5cf6 0%, #7c3aed 50%, #6d28d9 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(139, 92, 246, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
    },
    secondary: {
      background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(16, 185, 129, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
    },
    ghost: {
      background: 'rgba(255, 255, 255, 0.04)',
      color: 'var(--text-main, #f8fafc)',
      border: '1px solid rgba(255, 255, 255, 0.1)',
      boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.05)',
    },
    danger: {
      background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 50%, #b91c1c 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(239, 68, 68, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
    },
    glass: {
      background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.04) 100%)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      color: 'var(--text-main, #f8fafc)',
      border: '1px solid rgba(255, 255, 255, 0.12)',
      boxShadow: '0 4px 30px rgba(0, 0, 0, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.08)',
    },
    outline: {
      background: 'transparent',
      color: '#8b5cf6',
      border: '2px solid #8b5cf6',
      boxShadow: 'none',
    },
    gradient: {
      background: 'linear-gradient(135deg, #8b5cf6 0%, #ec4899 50%, #f59e0b 100%)',
      backgroundSize: '200% 200%',
      animation: 'gradientShift 3s ease infinite',
      color: '#ffffff',
      boxShadow: '0 4px 24px rgba(139, 92, 246, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
    },
    cyan: {
      background: 'linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(6, 182, 212, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
    },
  };

  // Merge all styles
  const combinedStyles = {
    ...baseStyles,
    ...(sizeStyles[size] || sizeStyles.default),
    ...(variantStyles[variant] || variantStyles.primary),
    ...style,
  };

  // Hover state handler
  const [isHovered, setIsHovered] = React.useState(false);
  const [isPressed, setIsPressed] = React.useState(false);

  // Enhanced hover styles with glow effects
  const hoverStyles = {
    primary: {
      boxShadow: '0 8px 35px rgba(139, 92, 246, 0.55), 0 0 50px rgba(139, 92, 246, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25)',
      transform: 'translateY(-3px) scale(1.02)',
    },
    secondary: {
      boxShadow: '0 8px 35px rgba(16, 185, 129, 0.55), 0 0 50px rgba(16, 185, 129, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25)',
      transform: 'translateY(-3px) scale(1.02)',
    },
    ghost: {
      background: 'rgba(255, 255, 255, 0.1)',
      borderColor: 'rgba(255, 255, 255, 0.25)',
      transform: 'translateY(-3px)',
      boxShadow: '0 8px 30px rgba(0, 0, 0, 0.3)',
    },
    danger: {
      boxShadow: '0 8px 35px rgba(239, 68, 68, 0.55), 0 0 50px rgba(239, 68, 68, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25)',
      transform: 'translateY(-3px) scale(1.02)',
    },
    glass: {
      background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.12) 0%, rgba(255, 255, 255, 0.06) 100%)',
      borderColor: 'rgba(255, 255, 255, 0.2)',
      boxShadow: '0 12px 45px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.12)',
      transform: 'translateY(-3px)',
    },
    outline: {
      background: 'rgba(139, 92, 246, 0.1)',
      boxShadow: '0 0 20px rgba(139, 92, 246, 0.3)',
      transform: 'translateY(-3px)',
    },
    gradient: {
      boxShadow: '0 8px 40px rgba(139, 92, 246, 0.45), 0 0 60px rgba(236, 72, 153, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25)',
      transform: 'translateY(-3px) scale(1.02)',
    },
    cyan: {
      boxShadow: '0 8px 35px rgba(6, 182, 212, 0.55), 0 0 50px rgba(6, 182, 212, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25)',
      transform: 'translateY(-3px) scale(1.02)',
    },
  };

  // Pressed styles
  const pressedStyles = {
    transform: 'translateY(-1px) scale(0.98)',
    filter: 'brightness(0.95)',
  };

  const activeStyles = isPressed && !disabled && !loading
    ? pressedStyles
    : isHovered && !disabled && !loading
      ? hoverStyles[variant] || hoverStyles.primary
      : {};

  const finalStyles = {
    ...combinedStyles,
    ...activeStyles,
    ...(glow && !disabled && {
      animation: 'pulseGlow 2s ease-in-out infinite',
    }),
  };

  return (
    <>
      <button
        type={type}
        style={finalStyles}
        disabled={disabled || loading}
        aria-disabled={disabled || loading}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => {
          setIsHovered(false);
          setIsPressed(false);
        }}
        onMouseDown={() => setIsPressed(true)}
        onMouseUp={() => setIsPressed(false)}
        className={className}
        {...props}
      >
        {/* Shimmer Effect Overlay */}
        <span
          style={{
            position: 'absolute',
            top: 0,
            left: '-100%',
            width: '100%',
            height: '100%',
            background: 'linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.15), transparent)',
            transition: 'left 0.5s ease',
            ...(isHovered && !loading && { left: '100%' }),
          }}
        />

        {/* Loading spinner */}
        {loading && (
          <svg
            style={{
              animation: 'spin 1s linear infinite',
              width: '1.125rem',
              height: '1.125rem',
              flexShrink: 0,
            }}
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              style={{ opacity: 0.25 }}
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              style={{ opacity: 0.85 }}
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}

        {/* Icon */}
        {icon && !loading && (
          <span style={{ flexShrink: 0, display: 'flex', alignItems: 'center' }}>{icon}</span>
        )}

        {/* Content */}
        <span style={{ position: 'relative', zIndex: 10 }}>{children}</span>
      </button>

      {/* Keyframe animations */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes pulseGlow {
          0%, 100% {
            box-shadow: 0 4px 20px rgba(139, 92, 246, 0.4), 0 0 30px rgba(139, 92, 246, 0.2);
          }
          50% {
            box-shadow: 0 4px 30px rgba(139, 92, 246, 0.6), 0 0 50px rgba(139, 92, 246, 0.35);
          }
        }
        @keyframes gradientShift {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
      `}</style>
    </>
  );
};

export default Button;
