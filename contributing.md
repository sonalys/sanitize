# Contributing Guidelines

Thank you for your interest in contributing!  
Please be sure to create a discussion around your problem or idea before contributing to the project.

## Before You Start
1. **Search for existing issues/PRs**  
   - Avoid duplicating work by checking open and closed issues.
2. **Open an issue first** (for features or bugs)  
   - This lets us discuss scope and approach before you start coding.

## 2. Development Workflow

1. **Fork the repo** and clone it locally:
```bash
   git clone https://github.com/<your-username>/<fork>.git
   cd <repo>
``` 

2. Create a feature branch:
```bash
    git checkout -b feat/issue-number
```

3. Add your code
4. Write tests
5. Run all checks locally
```bash
gofmt -w .
go test ./...
```
6. Clean commit message and history for the branch
7. Push your branch and open a pull request