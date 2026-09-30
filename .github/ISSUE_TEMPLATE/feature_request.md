name: Feature request
description: Suggest an idea for backseat
labels: [enhancement]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What are you trying to do that you cannot do today?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposal
      description: What should change? Keep harness-specific ideas out: backseat stays PTY-based and harness-agnostic.
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
