name: Bug report
description: Report something broken in backseat
labels: [bug]
body:
  - type: input
    id: version
    attributes:
      label: Version
      description: Commit SHA or release tag you ran
    validations:
      required: true
  - type: input
    id: os
    attributes:
      label: OS
      description: e.g. Ubuntu 24.04, macOS 15
    validations:
      required: true
  - type: textarea
    id: commands
    attributes:
      label: Commands run
      description: The exact relay, host, and expert commands you used
      render: shell
    validations:
      required: true
  - type: textarea
    id: what-happened
    attributes:
      label: What happened
      description: What you saw, including any error output or logs
      render: shell
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: What you expected
    validations:
      required: true
