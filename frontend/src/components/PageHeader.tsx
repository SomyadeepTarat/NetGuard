import React from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  icon?: React.ReactNode
  badge?: React.ReactNode
  actions?: React.ReactNode
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  icon,
  badge,
  actions,
}) => {
  return (
    <div className="page-header">
      <div className="page-header-text">
        <h1 className="page-title">
          {icon && <span style={{ display: 'inline-flex', color: 'var(--color-accent)' }}>{icon}</span>}
          <span>{title}</span>
          {badge}
        </h1>
        {description && <p className="page-desc">{description}</p>}
      </div>
      {actions && <div className="page-header-actions">{actions}</div>}
    </div>
  )
}
