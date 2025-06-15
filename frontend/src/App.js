import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, useNavigate, useLocation, useParams } from "react-router-dom";
import "./App.css";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import AuthCallback from "./components/AuthCallback";
import LoginButton from "./components/LoginButton";
import ProfilePage from "./components/ProfilePage";
import ProtectedRoute from "./components/ProtectedRoute";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

// Enhanced course data with sessions
const courseData = {
  masterclasses: [
    {
      id: 1,
      title: "Advanced React Patterns",
      description: "Deep dive into advanced React patterns including render props, compound components, and custom hooks for building scalable applications. This comprehensive course will transform your React development skills and teach you to build maintainable, reusable components.",
      duration: "2h 45m",
      views: "15.2K",
      instructor: "Sarah Chen",
      level: "Advanced",
      tags: ["React", "JavaScript", "Frontend", "Patterns"],
      sessions: [
        {id: 1, title: "Introduction to Advanced Patterns", duration: "15m", description: "Overview of React patterns and when to use them"},
        {id: 2, title: "Render Props Pattern", duration: "25m", description: "Master the render props pattern for component composition"},
        {id: 3, title: "Compound Components", duration: "30m", description: "Build flexible compound components like Accordion and Modal"},
        {id: 4, title: "Custom Hooks Deep Dive", duration: "35m", description: "Create powerful custom hooks for state management"},
        {id: 5, title: "Higher-Order Components", duration: "25m", description: "Advanced HOC patterns and best practices"},
        {id: 6, title: "Context API Mastery", duration: "20m", description: "Advanced Context patterns for state management"},
        {id: 7, title: "Performance Optimization", duration: "25m", description: "Optimize React apps using advanced patterns"}
      ],
      quiz: {
        questions: [
          {
            question: "What is the main benefit of the render props pattern?",
            options: ["Better performance", "Component reusability", "Smaller bundle size", "Easier debugging"],
            correct: 1
          },
          {
            question: "When should you use compound components?",
            options: ["For simple UI elements", "For complex, configurable components", "Only with hooks", "Never"],
            correct: 1
          },
          {
            question: "What makes a custom hook 'custom'?",
            options: ["It uses useState", "It starts with 'use'", "It's exported", "All of the above"],
            correct: 3
          }
        ]
      }
    },
    {
      id: 2,
      title: "System Design Masterclass",
      description: "Learn how to design scalable systems from industry experts. Cover databases, caching, load balancing, and microservices architecture. Perfect for senior engineers and architects.",
      duration: "3h 20m",
      views: "28.5K",
      instructor: "Michael Rodriguez",
      level: "Expert",
      tags: ["System Design", "Architecture", "Scalability", "Backend"],
      sessions: [
        {id: 1, title: "System Design Fundamentals", duration: "20m", description: "Core principles of distributed systems"},
        {id: 2, title: "Load Balancing Strategies", duration: "25m", description: "Round robin, weighted, and consistent hashing"},
        {id: 3, title: "Database Scaling", duration: "30m", description: "Horizontal vs vertical scaling, sharding"},
        {id: 4, title: "Caching Patterns", duration: "25m", description: "Redis, Memcached, and caching strategies"},
        {id: 5, title: "Microservices Architecture", duration: "35m", description: "Service decomposition and communication"},
        {id: 6, title: "Message Queues", duration: "20m", description: "Kafka, RabbitMQ, and async processing"},
        {id: 7, title: "Monitoring & Observability", duration: "25m", description: "Logging, metrics, and distributed tracing"}
      ],
      quiz: {
        questions: [
          {
            question: "What is the primary purpose of load balancing?",
            options: ["Security", "Distribute traffic evenly", "Data backup", "Code optimization"],
            correct: 1
          },
          {
            question: "Which caching strategy is best for read-heavy workloads?",
            options: ["Write-through", "Write-behind", "Cache-aside", "Write-around"],
            correct: 2
          }
        ]
      }
    },
    {
      id: 3,
      title: "AI/ML in Production",
      description: "Complete guide to deploying machine learning models in production environments with real-world examples and best practices. Learn MLOps, model monitoring, and scaling strategies.",
      duration: "2h 15m",
      views: "12.8K",
      instructor: "Dr. Anna Kowalski",
      level: "Advanced",
      tags: ["AI", "Machine Learning", "Production", "MLOps"],
      sessions: [
        {id: 1, title: "ML Production Overview", duration: "15m", description: "Challenges of ML in production"},
        {id: 2, title: "Model Versioning", duration: "20m", description: "MLflow and model lifecycle management"},
        {id: 3, title: "Containerizing ML Models", duration: "25m", description: "Docker and Kubernetes for ML"},
        {id: 4, title: "Model Serving Strategies", duration: "20m", description: "REST APIs, gRPC, and batch processing"},
        {id: 5, title: "Monitoring & Alerting", duration: "25m", description: "Model drift and performance monitoring"},
        {id: 6, title: "A/B Testing for ML", duration: "20m", description: "Experimental design for model evaluation"},
        {id: 7, title: "Scaling ML Systems", duration: "20m", description: "Auto-scaling and load balancing ML services"}
      ],
      quiz: {
        questions: [
          {
            question: "What is model drift?",
            options: ["Model getting slower", "Model accuracy decreasing over time", "Model size increasing", "Model crashes"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 4,
      title: "Cloud Architecture Mastery",
      description: "Master cloud architecture patterns, serverless computing, and multi-cloud strategies for enterprise applications.",
      duration: "4h 10m",
      views: "19.3K",
      instructor: "James Wilson",
      level: "Expert",
      tags: ["Cloud", "AWS", "Architecture", "Serverless"],
      sessions: [
        {id: 1, title: "Cloud Architecture Principles", duration: "25m", description: "Fundamentals of cloud-native design"},
        {id: 2, title: "Serverless Patterns", duration: "30m", description: "AWS Lambda, API Gateway, and event-driven architecture"},
        {id: 3, title: "Container Orchestration", duration: "35m", description: "EKS, ECS, and container strategies"},
        {id: 4, title: "Multi-Cloud Strategy", duration: "30m", description: "AWS, Azure, GCP integration patterns"},
        {id: 5, title: "Security in the Cloud", duration: "25m", description: "IAM, VPC, and security best practices"},
        {id: 6, title: "Cost Optimization", duration: "20m", description: "Resource optimization and cost management"},
        {id: 7, title: "Disaster Recovery", duration: "25m", description: "Backup strategies and business continuity"}
      ],
      quiz: {
        questions: [
          {
            question: "What is the main advantage of serverless architecture?",
            options: ["Lower costs", "No servers", "Automatic scaling", "All of the above"],
            correct: 3
          }
        ]
      }
    },
    {
      id: 5,
      title: "Advanced Database Design",
      description: "Deep dive into database optimization, indexing strategies, and NoSQL vs SQL decision making for high-performance applications.",
      duration: "3h 30m",
      views: "14.7K",
      instructor: "Lisa Zhang",
      level: "Advanced",
      tags: ["Database", "SQL", "NoSQL", "Performance"],
      sessions: [
        {id: 1, title: "Database Design Principles", duration: "20m", description: "Normalization and denormalization strategies"},
        {id: 2, title: "Indexing Strategies", duration: "30m", description: "B-trees, hash indexes, and composite indexes"},
        {id: 3, title: "Query Optimization", duration: "25m", description: "Execution plans and query tuning"},
        {id: 4, title: "NoSQL Patterns", duration: "30m", description: "Document, key-value, and graph databases"},
        {id: 5, title: "Transactions & ACID", duration: "25m", description: "Consistency models and transaction isolation"},
        {id: 6, title: "Database Scaling", duration: "30m", description: "Replication, sharding, and partitioning"},
        {id: 7, title: "Performance Monitoring", duration: "30m", description: "Database metrics and performance tuning"}
      ],
      quiz: {
        questions: [
          {
            question: "What does ACID stand for in database transactions?",
            options: ["Atomicity, Consistency, Isolation, Durability", "Async, Consistent, Isolated, Durable", "Atomic, Concurrent, Independent, Distributed", "None of the above"],
            correct: 0
          }
        ]
      }
    },
    {
      id: 6,
      title: "Microservices Architecture",
      description: "Complete guide to designing, building, and deploying microservices with service mesh, API gateways, and distributed systems.",
      duration: "3h 45m",
      views: "22.1K",
      instructor: "David Kumar",
      level: "Expert",
      tags: ["Microservices", "Architecture", "API", "Distributed Systems"],
      sessions: [
        {id: 1, title: "Microservices Overview", duration: "20m", description: "When and why to use microservices"},
        {id: 2, title: "Service Decomposition", duration: "30m", description: "Domain-driven design and service boundaries"},
        {id: 3, title: "API Gateway Patterns", duration: "25m", description: "Kong, AWS API Gateway, and routing strategies"},
        {id: 4, title: "Service Communication", duration: "30m", description: "REST, gRPC, and event-driven communication"},
        {id: 5, title: "Data Management", duration: "25m", description: "Database per service and data consistency"},
        {id: 6, title: "Service Mesh", duration: "30m", description: "Istio, Linkerd, and traffic management"},
        {id: 7, title: "Testing Strategies", duration: "25m", description: "Unit, integration, and contract testing"}
      ],
      quiz: {
        questions: [
          {
            question: "What is the main challenge with microservices?",
            options: ["Performance", "Complexity", "Cost", "Security"],
            correct: 1
          }
        ]
      }
    }
  ],

  careerpaths: [
    {
      id: 1,
      title: "Full-Stack Developer Roadmap",
      description: "Complete roadmap from beginner to senior full-stack developer with hands-on projects, portfolio building, and career advice.",
      duration: "1h 30m",
      views: "45.2K",
      instructor: "Alex Thompson",
      level: "All Levels",
      tags: ["Full-Stack", "Career", "Portfolio", "Development"],
      sessions: [
        {id: 1, title: "Full-Stack Overview", duration: "10m", description: "What it means to be a full-stack developer"},
        {id: 2, title: "Frontend Fundamentals", duration: "15m", description: "HTML, CSS, JavaScript mastery path"},
        {id: 3, title: "Backend Technologies", duration: "15m", description: "Node.js, Python, or Java - choosing your path"},
        {id: 4, title: "Database Skills", duration: "10m", description: "SQL and NoSQL database essentials"},
        {id: 5, title: "DevOps Basics", duration: "15m", description: "Git, Docker, and deployment strategies"},
        {id: 6, title: "Portfolio Projects", duration: "15m", description: "Building impressive projects for your portfolio"},
        {id: 7, title: "Job Search Strategy", duration: "10m", description: "Resume, interviews, and salary negotiation"}
      ],
      quiz: {
        questions: [
          {
            question: "What's the most important skill for a full-stack developer?",
            options: ["Knowing every technology", "Problem-solving ability", "Working fast", "Having certifications"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 2,
      title: "Product Manager Journey",
      description: "From technical background to product management: skills development, stakeholder management, and career transition strategies.",
      duration: "1h 45m",
      views: "23.1K",
      instructor: "Maria Garcia",
      level: "Intermediate",
      tags: ["Product Management", "Career Transition", "Strategy", "Leadership"],
      sessions: [
        {id: 1, title: "PM Role Overview", duration: "12m", description: "Understanding the product manager role"},
        {id: 2, title: "Technical to PM Transition", duration: "15m", description: "Leveraging your technical background"},
        {id: 3, title: "Product Strategy", duration: "18m", description: "Vision, roadmaps, and prioritization"},
        {id: 4, title: "User Research", duration: "15m", description: "Understanding customer needs and pain points"},
        {id: 5, title: "Stakeholder Management", duration: "15m", description: "Working with engineering, design, and business"},
        {id: 6, title: "Metrics & Analytics", duration: "15m", description: "Defining and tracking product success"},
        {id: 7, title: "PM Interview Prep", duration: "15m", description: "Case studies and interview strategies"}
      ],
      quiz: {
        questions: [
          {
            question: "What's the key difference between a project manager and product manager?",
            options: ["Project managers work with timelines", "Product managers focus on 'what' and 'why'", "No difference", "Product managers are more technical"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 3,
      title: "DevOps Career Path",
      description: "Navigate your way into DevOps with practical skills, industry certifications, tools mastery, and salary negotiation.",
      duration: "2h 10m",
      views: "31.7K",
      instructor: "Robert Kim",
      level: "Intermediate",
      tags: ["DevOps", "Career", "Certification", "Tools"],
      sessions: [
        {id: 1, title: "DevOps Fundamentals", duration: "15m", description: "Culture, practices, and methodologies"},
        {id: 2, title: "Essential Tools", duration: "20m", description: "Docker, Kubernetes, Jenkins, and Terraform"},
        {id: 3, title: "Cloud Platforms", duration: "18m", description: "AWS, Azure, GCP for DevOps engineers"},
        {id: 4, title: "CI/CD Pipelines", duration: "20m", description: "Building automated deployment pipelines"},
        {id: 5, title: "Monitoring & Logging", duration: "15m", description: "Prometheus, Grafana, ELK stack"},
        {id: 6, title: "Certifications Guide", duration: "12m", description: "AWS, Azure, Kubernetes certifications"},
        {id: 7, title: "Career Advancement", duration: "20m", description: "From junior to senior DevOps roles"}
      ],
      quiz: {
        questions: [
          {
            question: "What is the primary goal of DevOps?",
            options: ["Faster deployments", "Better collaboration between Dev and Ops", "Cost reduction", "Tool automation"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 4,
      title: "Data Science Career Guide",
      description: "Comprehensive guide to becoming a data scientist: skills, projects, interview preparation, and industry insights.",
      duration: "2h 25m",
      views: "38.9K",
      instructor: "Dr. Emily Davis",
      level: "All Levels",
      tags: ["Data Science", "Analytics", "Career", "Python"],
      sessions: [
        {id: 1, title: "Data Science Landscape", duration: "15m", description: "Understanding different data roles"},
        {id: 2, title: "Essential Skills", duration: "20m", description: "Statistics, programming, and domain knowledge"},
        {id: 3, title: "Python for Data Science", duration: "25m", description: "Pandas, NumPy, scikit-learn mastery"},
        {id: 4, title: "Machine Learning Basics", duration: "20m", description: "Supervised vs unsupervised learning"},
        {id: 5, title: "Portfolio Projects", duration: "20m", description: "Building impressive data science projects"},
        {id: 6, title: "Interview Preparation", duration: "25m", description: "Technical interviews and case studies"},
        {id: 7, title: "Industry Specializations", duration: "20m", description: "Finance, healthcare, tech, and retail"}
      ],
      quiz: {
        questions: [
          {
            question: "What's the most challenging part of a data science project?",
            options: ["Building models", "Data cleaning and preparation", "Presenting results", "Writing code"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 5,
      title: "UX/UI Designer Path",
      description: "From design fundamentals to senior designer role: portfolio development, user research, and design thinking methodologies.",
      duration: "1h 55m",
      views: "27.4K",
      instructor: "Sophie Laurent",
      level: "Beginner",
      tags: ["UX", "UI", "Design", "Portfolio"],
      sessions: [
        {id: 1, title: "Design Fundamentals", duration: "18m", description: "Color theory, typography, and composition"},
        {id: 2, title: "UX vs UI Design", duration: "12m", description: "Understanding the difference and overlap"},
        {id: 3, title: "User Research Methods", duration: "20m", description: "Interviews, surveys, and usability testing"},
        {id: 4, title: "Design Tools Mastery", duration: "15m", description: "Figma, Adobe XD, and prototyping tools"},
        {id: 5, title: "Information Architecture", duration: "15m", description: "Organizing content and navigation"},
        {id: 6, title: "Portfolio Development", duration: "20m", description: "Showcasing your design process"},
        {id: 7, title: "Design Career Growth", duration: "15m", description: "Junior to senior designer progression"}
      ],
      quiz: {
        questions: [
          {
            question: "What should be the focus of a UX designer?",
            options: ["Making things look pretty", "Understanding user needs", "Following design trends", "Using latest tools"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 6,
      title: "Tech Leadership Journey",
      description: "Transition from individual contributor to tech leader: team management, technical strategy, and executive communication.",
      duration: "2h 35m",
      views: "18.6K",
      instructor: "Mark Anderson",
      level: "Advanced",
      tags: ["Leadership", "Management", "Strategy", "Communication"],
      sessions: [
        {id: 1, title: "IC to Manager Transition", duration: "20m", description: "Mindset shift from doing to leading"},
        {id: 2, title: "Building High-Performing Teams", duration: "25m", description: "Hiring, mentoring, and team dynamics"},
        {id: 3, title: "Technical Strategy", duration: "20m", description: "Architecture decisions and technical debt"},
        {id: 4, title: "Stakeholder Communication", duration: "20m", description: "Translating technical concepts for executives"},
        {id: 5, title: "Performance Management", duration: "15m", description: "Setting goals and providing feedback"},
        {id: 6, title: "Managing Up", duration: "15m", description: "Working effectively with senior leadership"},
        {id: 7, title: "Leadership Challenges", duration: "20m", description: "Handling conflicts and difficult decisions"}
      ],
      quiz: {
        questions: [
          {
            question: "What's the biggest challenge for new tech managers?",
            options: ["Technical skills", "Time management", "Letting go of hands-on work", "Budget management"],
            correct: 2
          }
        ]
      }
    }
  ],

  crashcourses: [
    {
      id: 1,
      title: "JavaScript ES6+ Crash Course",
      description: "Master modern JavaScript features in just 2 hours. Arrow functions, promises, async/await, destructuring, and more.",
      duration: "2h 00m",
      views: "89.3K",
      instructor: "Ryan Miller",
      level: "Beginner",
      tags: ["JavaScript", "ES6", "Programming", "Fundamentals"],
      sessions: [
        {id: 1, title: "Modern JavaScript Overview", duration: "10m", description: "ES6+ features and browser support"},
        {id: 2, title: "Arrow Functions & Template Literals", duration: "15m", description: "Concise function syntax and string templates"},
        {id: 3, title: "Destructuring & Spread Operator", duration: "20m", description: "Extracting values and spreading arrays/objects"},
        {id: 4, title: "Promises & Async/Await", duration: "25m", description: "Handling asynchronous operations"},
        {id: 5, title: "Modules & Classes", duration: "20m", description: "Import/export and ES6 class syntax"},
        {id: 6, title: "Array Methods", duration: "15m", description: "map, filter, reduce, and other array methods"},
        {id: 7, title: "Practical Examples", duration: "15m", description: "Real-world JavaScript applications"}
      ],
      quiz: {
        questions: [
          {
            question: "What's the main advantage of arrow functions?",
            options: ["Faster execution", "Lexical 'this' binding", "Smaller file size", "Better debugging"],
            correct: 1
          },
          {
            question: "Which method would you use to transform an array?",
            options: ["forEach", "map", "filter", "reduce"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 2,
      title: "Docker Fundamentals",
      description: "Get up and running with Docker containers. Perfect for students and developers new to containerization technology.",
      duration: "1h 20m",
      views: "56.4K",
      instructor: "Carlos Mendez",
      level: "Beginner",
      tags: ["Docker", "Containers", "DevOps", "Tools"],
      sessions: [
        {id: 1, title: "What is Docker?", duration: "10m", description: "Containers vs virtual machines"},
        {id: 2, title: "Docker Installation", duration: "8m", description: "Setting up Docker on different platforms"},
        {id: 3, title: "Images and Containers", duration: "15m", description: "Understanding Docker images and containers"},
        {id: 4, title: "Dockerfile Basics", duration: "20m", description: "Creating custom Docker images"},
        {id: 5, title: "Docker Commands", duration: "12m", description: "Essential Docker CLI commands"},
        {id: 6, title: "Docker Compose", duration: "10m", description: "Multi-container applications"},
        {id: 7, title: "Best Practices", duration: "5m", description: "Docker security and optimization tips"}
      ],
      quiz: {
        questions: [
          {
            question: "What is the main benefit of using Docker?",
            options: ["Better performance", "Application portability", "Smaller code size", "Easier debugging"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 3,
      title: "Git & GitHub Essentials",
      description: "Version control fundamentals every developer needs to know. From basic commands to advanced workflows and collaboration.",
      duration: "1h 15m",
      views: "72.9K",
      instructor: "Jennifer Lee",
      level: "Beginner",
      tags: ["Git", "GitHub", "Version Control", "Collaboration"],
      sessions: [
        {id: 1, title: "Version Control Basics", duration: "8m", description: "Why version control matters"},
        {id: 2, title: "Git Setup", duration: "7m", description: "Installing and configuring Git"},
        {id: 3, title: "Basic Git Commands", duration: "15m", description: "add, commit, push, pull, clone"},
        {id: 4, title: "Branching Strategy", duration: "12m", description: "Creating and merging branches"},
        {id: 5, title: "GitHub Workflow", duration: "10m", description: "Pull requests and code reviews"},
        {id: 6, title: "Resolving Conflicts", duration: "8m", description: "Handling merge conflicts"},
        {id: 7, title: "Advanced Git", duration: "15m", description: "Rebasing, cherry-picking, and advanced workflows"}
      ],
      quiz: {
        questions: [
          {
            question: "What's the difference between 'git add' and 'git commit'?",
            options: ["No difference", "add stages changes, commit saves them", "add saves changes, commit pushes them", "commit is faster"],
            correct: 1
          }
        ]
      }
    },
    {
      id: 4,
      title: "Python Crash Course",
      description: "Learn Python programming from scratch in 90 minutes. Variables, functions, loops, and basic data structures.",
      duration: "1h 30m",
      views: "94.7K",
      instructor: "Ahmed Hassan",
      level: "Beginner",
      tags: ["Python", "Programming", "Basics", "Syntax"],
      sessions: [
        {id: 1, title: "Python Introduction", duration: "10m", description: "Why Python and installation"},
        {id: 2, title: "Variables & Data Types", duration: "12m", description: "Numbers, strings, booleans, and lists"},
        {id: 3, title: "Control Flow", duration: "15m", description: "if/else statements and loops"},
        {id: 4, title: "Functions", duration: "12m", description: "Defining and calling functions"},
        {id: 5, title: "Data Structures", duration: "15m", description: "Lists, dictionaries, and tuples"},
        {id: 6, title: "File Handling", duration: "8m", description: "Reading and writing files"},
        {id: 7, title: "Practice Project", duration: "18m", description: "Building a simple calculator"}
      ],
      quiz: {
        questions: [
          {
            question: "Which data type is ordered and changeable in Python?",
            options: ["Tuple", "Set", "List", "Dictionary"],
            correct: 2
          }
        ]
      }
    },
    {
      id: 5,
      title: "SQL Quick Start",
      description: "Database querying essentials for beginners. SELECT, JOIN, GROUP BY, and database design fundamentals.",
      duration: "1h 45m",
      views: "67.2K",
      instructor: "Patricia Wong",
      level: "Beginner",
      tags: ["SQL", "Database", "Queries", "Data"],
      sessions: [
        {id: 1, title: "Database Fundamentals", duration: "12m", description: "Tables, rows, columns, and relationships"},
        {id: 2, title: "SELECT Statements", duration: "15m", description: "Basic querying and filtering"},
        {id: 3, title: "WHERE and ORDER BY", duration: "12m", description: "Filtering and sorting results"},
        {id: 4, title: "JOIN Operations", duration: "20m", description: "INNER, LEFT, RIGHT, and FULL JOINs"},
        {id: 5, title: "GROUP BY & Aggregation", duration: "15m", description: "COUNT, SUM, AVG, and grouping data"},
        {id: 6, title: "INSERT, UPDATE, DELETE", duration: "12m", description: "Modifying database data"},
        {id: 7, title: "Database Design", duration: "19m", description: "Normalization and best practices"}
      ],
      quiz: {
        questions: [
          {
            question: "Which SQL command is used to retrieve data?",
            options: ["GET", "FETCH", "SELECT", "RETRIEVE"],
            correct: 2
          }
        ]
      }
    },
    {
      id: 6,
      title: "React Basics Crash Course",
      description: "Build your first React application in under 2 hours. Components, state, props, and event handling.",
      duration: "1h 50m",
      views: "83.1K",
      instructor: "Tom Bradley",
      level: "Beginner",
      tags: ["React", "JavaScript", "Components", "Frontend"],
      sessions: [
        {id: 1, title: "React Introduction", duration: "10m", description: "What is React and why use it?"},
        {id: 2, title: "Components Basics", duration: "15m", description: "Creating functional components"},
        {id: 3, title: "JSX Syntax", duration: "12m", description: "JavaScript XML and React elements"},
        {id: 4, title: "Props & State", duration: "20m", description: "Passing data and managing component state"},
        {id: 5, title: "Event Handling", duration: "15m", description: "onClick, onChange, and form handling"},
        {id: 6, title: "Conditional Rendering", duration: "10m", description: "Showing/hiding content dynamically"},
        {id: 7, title: "Building a Todo App", duration: "28m", description: "Practical React application"}
      ],
      quiz: {
        questions: [
          {
            question: "What is JSX?",
            options: ["A new programming language", "JavaScript XML", "A React framework", "A build tool"],
            correct: 1
          }
        ]
      }
    }
  ]
};

// Get all courses from all categories
const getAllCourses = () => {
  const allCourses = [];
  Object.keys(courseData).forEach(category => {
    courseData[category].forEach(course => {
      allCourses.push({ ...course, category });
    });
  });
  return allCourses;
};

const VideoCard = ({ title, description, duration, views, instructor, level, tags, onClick }) => (
  <div className="glass-card group cursor-pointer" onClick={onClick}>
    <div className="aspect-video bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg mb-4 flex items-center justify-center relative overflow-hidden">
      <div className="w-16 h-16 bg-white/20 rounded-full flex items-center justify-center backdrop-blur-sm group-hover:scale-110 transition-transform duration-300">
        <svg className="w-8 h-8 text-white ml-1" fill="currentColor" viewBox="0 0 24 24">
          <path d="M8 5v14l11-7z"/>
        </svg>
      </div>
      <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
      <div className="absolute top-3 right-3">
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
          level === 'Expert' ? 'bg-red-500/80 text-white' :
          level === 'Advanced' ? 'bg-orange-500/80 text-white' :
          level === 'Intermediate' ? 'bg-yellow-500/80 text-black' :
          'bg-green-500/80 text-white'
        }`}>
          {level}
        </span>
      </div>
    </div>
    <h3 className="text-white font-semibold mb-2 group-hover:text-blue-300 transition-colors">{title}</h3>
    <p className="text-gray-300 text-sm mb-3 line-clamp-2">{description}</p>
    <div className="flex justify-between items-center text-xs text-gray-400 mb-3">
      <span>{duration}</span>
      <span>{views} views</span>
    </div>
    <div className="flex justify-between items-center mb-3">
      <span className="text-sm text-gray-300">by {instructor}</span>
    </div>
    <div className="flex flex-wrap gap-1">
      {tags.slice(0, 3).map((tag, index) => (
        <span key={index} className="text-xs bg-white/10 text-gray-300 px-2 py-1 rounded-full">
          {tag}
        </span>
      ))}
    </div>
  </div>
);

const CourseDetail = () => {
  const { category, courseId } = useParams();
  const navigate = useNavigate();
  const [currentSession, setCurrentSession] = useState(1);
  const [completedSessions, setCompletedSessions] = useState(new Set());
  const [showQuiz, setShowQuiz] = useState(false);
  const [quizAnswers, setQuizAnswers] = useState({});
  const [quizCompleted, setQuizCompleted] = useState(false);

  const course = courseData[category]?.find(c => c.id === parseInt(courseId));

  if (!course) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="glass-card p-8 text-center">
          <h2 className="text-white text-2xl mb-4">Course not found</h2>
          <button onClick={() => navigate('/')} className="glass-button">
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  const currentSessionData = course.sessions.find(s => s.id === currentSession);
  const progress = (completedSessions.size / course.sessions.length) * 100;
  const isLastSession = currentSession === course.sessions.length;

  const handleCompleteSession = () => {
    setCompletedSessions(prev => new Set([...prev, currentSession]));
    if (isLastSession) {
      setShowQuiz(true);
    } else {
      setCurrentSession(currentSession + 1);
    }
  };

  const handleQuizAnswer = (questionIndex, answerIndex) => {
    setQuizAnswers(prev => ({
      ...prev,
      [questionIndex]: answerIndex
    }));
  };

  const submitQuiz = () => {
    setQuizCompleted(true);
  };

  const getQuizScore = () => {
    let correct = 0;
    course.quiz.questions.forEach((question, index) => {
      if (quizAnswers[index] === question.correct) {
        correct++;
      }
    });
    return Math.round((correct / course.quiz.questions.length) * 100);
  };

  if (showQuiz) {
    return (
      <div className="min-h-screen bg-black px-6 py-20">
        <div className="max-w-4xl mx-auto">
          <div className="glass-card p-8 mb-8">
            <button
              onClick={() => navigate(`/${category}`)}
              className="glass-button mb-6 inline-flex items-center"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
              </svg>
              Back to Course List
            </button>

            <h1 className="text-3xl font-bold text-white mb-4">Final Assessment</h1>
            <h2 className="text-xl text-gray-300 mb-8">{course.title}</h2>

            {!quizCompleted ? (
              <>
                <p className="text-gray-300 mb-8">Complete this quiz to finish the course and receive your certificate.</p>
                
                {course.quiz.questions.map((question, qIndex) => (
                  <div key={qIndex} className="mb-8">
                    <h3 className="text-white text-lg font-semibold mb-4">
                      {qIndex + 1}. {question.question}
                    </h3>
                    <div className="grid gap-3">
                      {question.options.map((option, oIndex) => (
                        <button
                          key={oIndex}
                          onClick={() => handleQuizAnswer(qIndex, oIndex)}
                          className={`text-left p-4 rounded-lg border transition-all ${
                            quizAnswers[qIndex] === oIndex
                              ? 'bg-blue-500/20 border-blue-400 text-white'
                              : 'bg-white/5 border-white/20 text-gray-300 hover:bg-white/10'
                          }`}
                        >
                          {String.fromCharCode(65 + oIndex)}. {option}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}

                <button
                  onClick={submitQuiz}
                  disabled={Object.keys(quizAnswers).length !== course.quiz.questions.length}
                  className="glass-button disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Submit Quiz
                </button>
              </>
            ) : (
              <div className="text-center">
                <div className="mb-8">
                  <div className={`text-6xl font-bold mb-4 ${
                    getQuizScore() >= 80 ? 'text-green-400' : getQuizScore() >= 60 ? 'text-yellow-400' : 'text-red-400'
                  }`}>
                    {getQuizScore()}%
                  </div>
                  <h3 className="text-2xl text-white mb-2">
                    {getQuizScore() >= 80 ? 'Excellent!' : getQuizScore() >= 60 ? 'Good Job!' : 'Keep Learning!'}
                  </h3>
                  <p className="text-gray-300">
                    You got {Object.values(quizAnswers).filter((answer, index) => answer === course.quiz.questions[index].correct).length} out of {course.quiz.questions.length} questions correct.
                  </p>
                </div>
                
                <div className="flex justify-center gap-4">
                  <button
                    onClick={() => navigate(`/${category}`)}
                    className="glass-button"
                  >
                    Browse More Courses
                  </button>
                  <button
                    onClick={() => navigate('/')}
                    className="glass-button"
                  >
                    Back to Home
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="flex">
        {/* Sidebar - Sessions List */}
        <div className="w-80 bg-black/50 backdrop-blur-lg border-r border-white/10 p-6 overflow-y-auto max-h-screen">
          <button
            onClick={() => navigate(`/${category}`)}
            className="glass-button mb-6 w-full inline-flex items-center justify-center"
          >
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
            </svg>
            Back to Course List
          </button>

          <h2 className="text-white text-xl font-bold mb-4">{course.title}</h2>
          
          {/* Progress Bar */}
          <div className="mb-6">
            <div className="flex justify-between text-sm text-gray-300 mb-2">
              <span>Progress</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </div>

          {/* Sessions List */}
          <div className="space-y-2">
            {course.sessions.map((session) => (
              <button
                key={session.id}
                onClick={() => setCurrentSession(session.id)}
                className={`w-full text-left p-4 rounded-lg border transition-all ${
                  currentSession === session.id
                    ? 'bg-blue-500/20 border-blue-400 text-white'
                    : completedSessions.has(session.id)
                    ? 'bg-green-500/10 border-green-400 text-green-300'
                    : 'bg-white/5 border-white/20 text-gray-300 hover:bg-white/10'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-sm">Session {session.id}</span>
                  <span className="text-xs">{session.duration}</span>
                </div>
                <div className="text-sm opacity-90">{session.title}</div>
                {completedSessions.has(session.id) && (
                  <div className="flex items-center mt-2">
                    <svg className="w-4 h-4 text-green-400 mr-1" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/>
                    </svg>
                    <span className="text-xs text-green-400">Completed</span>
                  </div>
                )}
              </button>
            ))}
          </div>

          {/* Quiz Button */}
          {completedSessions.size === course.sessions.length && (
            <button
              onClick={() => setShowQuiz(true)}
              className="w-full mt-4 glass-button bg-green-500/20 border-green-400 text-green-300 hover:bg-green-500/30"
            >
              Take Final Quiz
            </button>
          )}
        </div>

        {/* Main Content */}
        <div className="flex-1 p-8">
          <div className="max-w-4xl mx-auto">
            {/* Course Header */}
            <div className="glass-card p-6 mb-8">
              <h1 className="text-3xl font-bold text-white mb-2">{course.title}</h1>
              <p className="text-gray-300 mb-4">{course.description}</p>
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span>by {course.instructor}</span>
                <span>•</span>
                <span>{course.duration} total</span>
                <span>•</span>
                <span>{course.views} views</span>
                <span>•</span>
                <span className={`px-2 py-1 rounded-full text-xs ${
                  course.level === 'Expert' ? 'bg-red-500/80 text-white' :
                  course.level === 'Advanced' ? 'bg-orange-500/80 text-white' :
                  course.level === 'Intermediate' ? 'bg-yellow-500/80 text-black' :
                  'bg-green-500/80 text-white'
                }`}>
                  {course.level}
                </span>
              </div>
            </div>

            {/* Current Session */}
            <div className="glass-card p-8 mb-8">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-white">
                  Session {currentSessionData.id}: {currentSessionData.title}
                </h2>
                <span className="text-gray-400">{currentSessionData.duration}</span>
              </div>

              {/* Video Placeholder */}
              <div className="aspect-video bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg mb-6 flex items-center justify-center relative overflow-hidden">
                <div className="w-20 h-20 bg-white/20 rounded-full flex items-center justify-center backdrop-blur-sm">
                  <svg className="w-10 h-10 text-white ml-1" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M8 5v14l11-7z"/>
                  </svg>
                </div>
                <div className="absolute bottom-4 left-4 glass-button py-2 px-4">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
                  </svg>
                  Play Video
                </div>
              </div>

              <p className="text-gray-300 mb-6 text-lg leading-relaxed">
                {currentSessionData.description}
              </p>

              <div className="flex justify-between items-center">
                <div className="flex gap-4">
                  {currentSession > 1 && (
                    <button
                      onClick={() => setCurrentSession(currentSession - 1)}
                      className="glass-button inline-flex items-center"
                    >
                      <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
                      </svg>
                      Previous Session
                    </button>
                  )}
                </div>
                
                <button
                  onClick={handleCompleteSession}
                  className="glass-button bg-blue-500/20 border-blue-400 text-blue-300 hover:bg-blue-500/30"
                >
                  {isLastSession ? 'Complete Course' : 'Complete & Continue'}
                  <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7"/>
                  </svg>
                </button>
              </div>
            </div>

            {/* Course Tags */}
            <div className="glass-card p-6">
              <h3 className="text-white font-semibold mb-4">Course Topics</h3>
              <div className="flex flex-wrap gap-2">
                {course.tags.map((tag, index) => (
                  <span key={index} className="bg-white/10 text-gray-300 px-3 py-1 rounded-full text-sm">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const SearchBar = ({ searchTerm, setSearchTerm, placeholder }) => (
  <div className="relative mb-8">
    <div className="glass-card p-0 overflow-hidden">
      <div className="flex items-center">
        <svg className="w-6 h-6 text-gray-400 ml-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
        <input
          type="text"
          placeholder={placeholder}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-transparent text-white placeholder-gray-400 px-4 py-4 focus:outline-none text-lg"
        />
      </div>
    </div>
  </div>
);

const FilterBar = ({ selectedLevel, setSelectedLevel, selectedTags, setSelectedTags, allTags }) => (
  <div className="glass-card mb-8 p-4">
    <div className="flex flex-wrap gap-4 items-center">
      <h3 className="text-white font-semibold">Filters:</h3>
      
      <div className="flex items-center gap-2">
        <span className="text-gray-300 text-sm">Level:</span>
        <select
          value={selectedLevel}
          onChange={(e) => setSelectedLevel(e.target.value)}
          className="bg-white/10 text-white border border-white/20 rounded-lg px-3 py-1 text-sm focus:outline-none focus:border-white/40"
        >
          <option value="">All Levels</option>
          <option value="Beginner">Beginner</option>
          <option value="Intermediate">Intermediate</option>
          <option value="Advanced">Advanced</option>
          <option value="Expert">Expert</option>
          <option value="All Levels">All Levels</option>
        </select>
      </div>

      <div className="flex flex-wrap gap-2">
        <span className="text-gray-300 text-sm">Tags:</span>
        {allTags.map(tag => (
          <button
            key={tag}
            onClick={() => {
              setSelectedTags(prev =>
                prev.includes(tag)
                  ? prev.filter(t => t !== tag)
                  : [...prev, tag]
              );
            }}
            className={`text-xs px-2 py-1 rounded-full transition-all ${
              selectedTags.includes(tag)
                ? 'bg-blue-500/80 text-white'
                : 'bg-white/10 text-gray-300 hover:bg-white/20'
            }`}
          >
            {tag}
          </button>
        ))}
      </div>
    </div>
  </div>
);

const CoursePage = ({ type, title, subtitle, backgroundImage, gradient }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLevel, setSelectedLevel] = useState('');
  const [selectedTags, setSelectedTags] = useState([]);
  const navigate = useNavigate();

  const courses = courseData[type] || [];
  const allTags = [...new Set(courses.flatMap(course => course.tags))];

  const filteredCourses = courses.filter(course => {
    const matchesSearch = course.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         course.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         course.instructor.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         course.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesLevel = !selectedLevel || course.level === selectedLevel;
    
    const matchesTags = selectedTags.length === 0 || 
                       selectedTags.some(tag => course.tags.includes(tag));
    
    return matchesSearch && matchesLevel && matchesTags;
  });

  return (
    <div
      className="min-h-screen relative px-6 py-20"
      style={{
        backgroundImage: `linear-gradient(${gradient}), url(${backgroundImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundAttachment: 'fixed'
      }}
    >
      <div className="absolute inset-0 bg-black/40 backdrop-blur-[1px]"></div>
      
      <div className="relative z-10 max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <button
            onClick={() => navigate('/')}
            className="glass-button mb-8 inline-flex items-center"
          >
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
            </svg>
            Back to Home
          </button>
          
          <h1 className="text-4xl md:text-6xl font-bold text-white mb-4 tracking-tight">
            {title}
          </h1>
          <p className="text-lg md:text-xl text-gray-200 max-w-3xl mx-auto leading-relaxed mb-8">
            {subtitle}
          </p>
          <div className="text-gray-300">
            <span className="text-2xl font-bold">{filteredCourses.length}</span> courses available
          </div>
        </div>

        {/* Search and Filters */}
        <SearchBar
          searchTerm={searchTerm}
          setSearchTerm={setSearchTerm}
          placeholder={`Search ${title.toLowerCase()}...`}
        />

        <FilterBar
          selectedLevel={selectedLevel}
          setSelectedLevel={setSelectedLevel}
          selectedTags={selectedTags}
          setSelectedTags={setSelectedTags}
          allTags={allTags}
        />

        {/* Course Grid */}
        {filteredCourses.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {filteredCourses.map((course) => (
              <VideoCard
                key={course.id}
                {...course}
                onClick={() => navigate(`/${type}/${course.id}`)}
              />
            ))}
          </div>
        ) : (
          <div className="text-center py-16">
            <div className="glass-card inline-block p-8">
              <svg className="w-16 h-16 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
              <h3 className="text-white text-xl font-semibold mb-2">No courses found</h3>
              <p className="text-gray-300">Try adjusting your search or filters to find more courses.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const Section = ({ id, title, subtitle, backgroundImage, videos, gradient }) => {
  const navigate = useNavigate();

  return (
    <section
      id={id}
      className="min-h-screen relative flex items-center justify-center px-6 py-20"
      style={{
        backgroundImage: `linear-gradient(${gradient}), url(${backgroundImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundAttachment: 'fixed'
      }}
    >
      <div className="absolute inset-0 bg-black/40 backdrop-blur-[1px]"></div>
      
      <div className="relative z-10 max-w-7xl mx-auto w-full">
        <div className="text-center mb-16">
          <h1 className="text-5xl md:text-7xl font-bold text-white mb-6 tracking-tight">
            {title}
          </h1>
          <p className="text-xl md:text-2xl text-gray-200 max-w-3xl mx-auto leading-relaxed">
            {subtitle}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {videos.map((video, index) => (
            <VideoCard
              key={index}
              {...video}
              onClick={() => navigate(`/${id}/${video.id}`)}
            />
          ))}
        </div>

        <div className="text-center mt-12">
          <button
            onClick={() => navigate(`/${id}`)}
            className="glass-button"
          >
            View All {title}
            <svg className="w-5 h-5 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3"/>
            </svg>
          </button>
        </div>
      </div>
    </section>
  );
};

const Navigation = () => {
  const [activeSection, setActiveSection] = useState('masterclasses');
  const location = useLocation();
  const { isAuthenticated, user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (location.pathname === '/') {
      const handleScroll = () => {
        const sections = ['masterclasses', 'careerpaths', 'crashcourses'];
        const scrollPosition = window.scrollY + 100;

        sections.forEach(section => {
          const element = document.getElementById(section);
          if (element) {
            const { offsetTop, offsetHeight } = element;
            if (scrollPosition >= offsetTop && scrollPosition < offsetTop + offsetHeight) {
              setActiveSection(section);
            }
          }
        });
      };

      window.addEventListener('scroll', handleScroll);
      return () => window.removeEventListener('scroll', handleScroll);
    }
  }, [location.pathname]);

  const scrollToSection = (sectionId) => {
    document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth' });
  };

  if (location.pathname !== '/') {
    return null;
  }

  return (
    <nav className="fixed top-6 left-1/2 transform -translate-x-1/2 z-50">
      <div className="glass-nav flex space-x-1 items-center">
        {[
          { id: 'masterclasses', label: 'Masterclasses' },
          { id: 'careerpaths', label: 'Career Paths' },
          { id: 'crashcourses', label: 'Crash Courses' }
        ].map(({ id, label }) => (
          <button
            key={id}
            onClick={() => scrollToSection(id)}
            className={`px-6 py-3 rounded-lg text-sm font-medium transition-all duration-300 ${
              activeSection === id
                ? 'bg-white/20 text-white shadow-lg'
                : 'text-gray-300 hover:text-white hover:bg-white/10'
            }`}
          >
            {label}
          </button>
        ))}
        
        {/* Profile/Login Button */}
        {isAuthenticated ? (
          <button
            onClick={() => navigate('/profile')}
            className="ml-4 px-4 py-3 rounded-lg text-sm font-medium bg-blue-500/20 text-blue-300 hover:bg-blue-500/30 border border-blue-400/50 transition-all duration-300 flex items-center"
          >
            <img 
              src={user?.picture} 
              alt="Profile" 
              className="w-6 h-6 rounded-full mr-2"
            />
            {user?.name?.split(' ')[0] || 'Profile'}
          </button>
        ) : (
          <button
            onClick={() => navigate('/login')}
            className="ml-4 px-4 py-3 rounded-lg text-sm font-medium bg-green-500/20 text-green-300 hover:bg-green-500/30 border border-green-400/50 transition-all duration-300"
          >
            Sign In
          </button>
        )}
      </div>
    </nav>
  );
};

const HomePage = () => {
  const masterclassVideos = courseData.masterclasses.slice(0, 3);
  const careerPathVideos = courseData.careerpaths.slice(0, 3);
  const crashCourseVideos = courseData.crashcourses.slice(0, 3);

  return (
    <>
      <Navigation />
      <Section
        id="masterclasses"
        title="UIS Masterclasses"
        subtitle="Deep-dive into advanced topics with industry experts. Comprehensive courses designed for professionals looking to master complex skills and cutting-edge technologies."
        backgroundImage="https://images.pexels.com/photos/2330137/pexels-photo-2330137.jpeg"
        videos={masterclassVideos}
        gradient="135deg, rgba(79, 70, 229, 0.4) 0%, rgba(147, 51, 234, 0.4) 100%"
      />
      <Section
        id="careerpaths"
        title="UIS Career Paths"
        subtitle="Structured learning journeys to advance your career. From entry-level to leadership roles, discover the skills and knowledge needed to achieve your professional goals."
        backgroundImage="https://images.unsplash.com/photo-1522211988038-6fcbb8c12c7e?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2Mzl8MHwxfHNlYXJjaHwyfHxsZWFybmluZ3xlbnwwfHx8YmxhY2t8MTc0OTc0MzU4NHww&ixlib=rb-4.1.0&q=85"
        videos={careerPathVideos}
        gradient="135deg, rgba(16, 185, 129, 0.4) 0%, rgba(59, 130, 246, 0.4) 100%"
      />
      <Section
        id="crashcourses"
        title="UIS Student Crash Courses"
        subtitle="Quick, intensive courses for rapid skill acquisition. Perfect for students who need to learn essential concepts quickly and efficiently."
        backgroundImage="https://images.unsplash.com/photo-1494178270175-e96de2971df9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2Mzl8MHwxfHNlYXJjaHwzfHxsZWFybmluZ3xlbnwwfHx8YmxhY2t8MTc0OTc0MzU4NHww&ixlib=rb-4.1.0&q=85"
        videos={crashCourseVideos}
        gradient="135deg, rgba(245, 101, 101, 0.4) 0%, rgba(251, 191, 36, 0.4) 100%"
      />
    </>
  );
};

function App() {
  return (
    <AuthProvider>
      <div className="App">
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<LoginButton />} />
            <Route path="/auth/callback" element={<AuthCallback />} />
            <Route path="/auth/error" element={<LoginButton />} />
            <Route 
              path="/profile" 
              element={
                <ProtectedRoute>
                  <ProfilePage />
                </ProtectedRoute>
              } 
            />
            <Route path="/masterclasses" element={
              <CoursePage
                type="masterclasses"
                title="UIS Masterclasses"
                subtitle="Deep-dive into advanced topics with industry experts. Comprehensive courses designed for professionals looking to master complex skills and cutting-edge technologies."
                backgroundImage="https://images.pexels.com/photos/2330137/pexels-photo-2330137.jpeg"
                gradient="135deg, rgba(79, 70, 229, 0.4) 0%, rgba(147, 51, 234, 0.4) 100%"
              />
            } />
            <Route path="/careerpaths" element={
              <CoursePage
                type="careerpaths"
                title="UIS Career Paths"
                subtitle="Structured learning journeys to advance your career. From entry-level to leadership roles, discover the skills and knowledge needed to achieve your professional goals."
                backgroundImage="https://images.unsplash.com/photo-1522211988038-6fcbb8c12c7e?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2Mzl8MHwxfHNlYXJjaHwyfHxsZWFybmluZ3xlbnwwfHx8YmxhY2t8MTc0OTc0MzU4NHww&ixlib=rb-4.1.0&q=85"
                gradient="135deg, rgba(16, 185, 129, 0.4) 0%, rgba(59, 130, 246, 0.4) 100%"
              />
            } />
            <Route path="/crashcourses" element={
              <CoursePage
                type="crashcourses"
                title="UIS Student Crash Courses"
                subtitle="Quick, intensive courses for rapid skill acquisition. Perfect for students who need to learn essential concepts quickly and efficiently."
                backgroundImage="https://images.unsplash.com/photo-1494178270175-e96de2971df9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2Mzl8MHwxfHNlYXJjaHwzfHxsZWFybmluZ3xlbnwwfHx8YmxhY2t8MTc0OTc0MzU4NHww&ixlib=rb-4.1.0&q=85"
                gradient="135deg, rgba(245, 101, 101, 0.4) 0%, rgba(251, 191, 36, 0.4) 100%"
              />
            } />
            <Route path="/:category/:courseId" element={<CourseDetail />} />
          </Routes>
        </BrowserRouter>
      </div>
    </AuthProvider>
  );
}

export default App;
