---
title: "Getting Started With GET Curl Commands"
description: ""
date: 2023-09-16T09:36:41.827Z
cascade:
  showReadingTime: true
tags:
- Getting Started
---
## Getting Started With GET Curl Commands

### Introduction to curl

A `curl` command is a tool used on the terminal to make network requests  using various protocols. `curl` is designed to aid with the data transfer to and from a server without the need for a web browser. With `curl` ,you can upload or download files, send requests to API endpoints to simulate user interaction from the terminal  using a supported protocol such as HTTPs, FTP, and more.

**Explanation of GET requests**

Webpages display content to the end-user by requesting for resources from the server.These requests are commonly made using a GET HTTP request, often accompanied by query parameters when necessary.

This guide shows you how to run GET requests using a  `curl` commands on the terminal.

**Prerequisites**

1. A Mac, Windows or Linux laptop
2. Access to the terminal
3. Have curl installed in your machine.

To verify that curl is installed by run the command `curl --version` on the terminal. If properly installed, it will output the curl version installed.

### Sending GET Requests with Curl

The GET command in `curl` is used to perform a GET request to the specified URL and retrieve user content from the server. The basic syntax for GET commands is as follows:
`curl [OPTIONS] [URL]`
`[OPTIONS]` - curl parameters such as `-o` to specify where to save the output.

`[URL]` - specify the URL or sequence of URLs you want to make a request to.

The `curl` request below performa a GET HTTTP request and fetches the content on the specified URL then prints the response body on the terminal

`curl https://documentwrite.dev/`

### Usage

**Downloading an image using curl**

To download this image, <https://documentwrite.dev/wp-content/uploads/2021/08/document-write-logo.png>, using curl, you will follow the following steps on your terminal:

1. Open the terminal or command prompt.
2. Navigate to the path you want to save the image. In this case the pictures directory using the command `cd pictures`
3. Run the following command to command to download the image:

```java
curl -o logo.png https://documentwrite.dev/wp-content/uploads/2021/08/document-write-logo.png
```

The command above does the following:
`-o logo.png` ****specifies the name of the file where to save the output of the response.

[`https://documentwrite.dev/wp-content/uploads/2021/08/document-write-logo.png`](https://documentwrite.dev/wp-content/uploads/2021/08/document-write-logo.png) is the url of the logo you want to download.

Check that the image file is downloaded successfully to the pictures folder.

### Conclusion

In this guide, we learned about curl and how to use the GET curl command to download an image from a URL. Curl is a powerful tool that can be used for various data transfer tasks, and its simplicity makes it accessible even to non-coders.

Remember to adjust the command and URL according to your specific use case.