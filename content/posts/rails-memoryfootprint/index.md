# Optimizing your Ruby on Rails app for improved performance and reduced memory footprint

Users desire apps that run smoothly, load fast, and don't crash. But what determines an app's performance? There are two key factors: performance and memory usage.
Performance refers to how fast your app loads for users. Memory footprint is the amount of system memory your app  uses. If your app is slow or hogs too much memory, users won't stick around. That's where optimizing your Ruby on Rails app becomes essential.

In this article, we'll explore techniques that enhance performance and reduce memory usage, ensuring user satisfaction and the success of your app.

## Understanding performance and memory footprint

The **performance** of an app refers to how fast your app loads for the end-users. As a developer, app performance should always be a priority even as you are adding new features and architecting your app.

**Memory footprint** refers to how much system memory or RAM space your app uses while it's running. Most computers have a finite amount of memory therefore, excessive memory usage can lead to freezing or crashes, degrading the user experience. Developers must find ways to minimize their app's memory footprint.

## Goals of optimization

The main goals of optimizing memory use and app performance are:

1. **User satisfaction**. Your goal as a developer is to get as many users as possible to use your app and to ensure that they enjoy interacting with the app.
2. **Business Scalability**. Optimized performance and reduced memory usage enable your business to scale, attracting more customers and generating revenue. It validates your efforts as a developer and ensures wider adoption of your technology and keeps the investors happy.

But how do you optimize your Rails app? In the next section, you'll learn about various techniques you can use to optimize the performance and memory usage of your app:

## Techniques for optimization
  
### Lazy loading

Lazy loading involves loading webpage components on demand, as the user needs them, rather than downloading the entire webpage at once. This prevents noticeable lagging while webpage content gets downloaded. For example, a blogging app could be architectured to dynamically load posts as the user scrolls, preventing memory overload. For instance:

```ruby
# articles_controller.rb

class ArticlesController < ApplicationController
  def index
    @articles = Article.limit(10) # Load only 10 articles initially
  end
  # Load more articles when the user clicks on the load more button
  def load_more_articles
    @articles = Article.limit(10).offset(params[:offset])
    render partial: 'articles/article', collection: @articles
  end
end
```

In Rails, you should write your code so that data is queried from your database as required. The fewer the SQL queries made to the database at a single time, the better the app's performance. Alternatively, you can perform all the heavy database queries in the background so not to freeze the UI.

Lazy loading leads to quicker initial load time and doesn't hog server/client resources every time they access an app.

### Optimize your database queries

Writing inefficient database queries slows down apps and leads to excessive memory consumption, both of which will plummet the app's performance. In Rails, N+1 queries are a major performance problem. They occur when you query the database multiple times for related records, resulting in slower response times.
For example, in your blog app, you may have two models: `Article` and `Comment`. N+1 will occur when you write two queries; one to fetch a list of all articles and another to fetch all the comments associated with each article.

```ruby
// Fetch all the articles
articles = Article.all

// Loop through all the articles and find the number of comments
articles.each do |article|
  count = article.comment.count
end
```

To optimize N+1 queries:

1. Use the [Bullet gem](https://github.com/flyerhzm/bullet) to help detect the N+1 queries in your apps.
2. Use Active Record's eager loading to write memory-efficient database queries. Active Record has an `eager_load` function that gets all the associated data using a left outer join to combine the requests into a single query. To make the code snippet above performant, you should use `articles = Article.includes(:comments)` to fetch articles and associated comments in a single query.
3. Use indexes to reduce how much data your queries need to read and process from the database. Indexed queries reduces query response time and make it easy to scale an app without affecting its performance.
4. Use Active Record to cache recent queries. Therefore instead of feching data from the database for all subsequent similar requests, it's best to fetch the data from the Active record cache.

Optimizing database queries is crucial for app performance. By using Active Record's eager loading, indexing smartly, and leveraging cache, you can significantly boost your app's speed and efficiency.

### Use memory profiling tools

Memory profiling tools are tools that are used to monitor and identify memory leaks in an app that could lead to app lagging or crashing. Ruby uses a Garbage Collector to automatically allocate and deallocate memory from objects which optimizes memory. However, sometimes the Garbage Collector fails to deallocate memory from objects that are no longer being used leading to memory leaks. You therefore need to use a memory profiler tool or memory profiler gems such as [ruby-prof](https://rubygems.org/gems/ruby-prof/versions/0.16.2?locale=en) to identify which objects are in use and how much memory is allocated to each.

For instance, you can use the built-in Ruby profiler by running `ruby -rprile script.rb` which tells Ruby to require the `profile` library and then run the `script.rb` file. Once the script is executed successfully or you kill the ruby process, the `profile` library will print out a performance profile on your terminal. You can then use a profiling tool to identify methods and parts of code that cause the highest memory usage and fix these memory issues.

### Caching

Caching is the practice of storing the response data returned from the server when a request is made and reusing the data for similar requests. The more requests you make to the server, the slower the app gets, especially as the app grows and the data being fetched increases. Caching is the most effective way of improving your app's performance.

The following are some caching techniques you can use in your Rails apps:

- **Memory caching**. Ruby has built-in caching which lets you cache your fragments, pages, and actions to reuse when responding to requests. Rails provides fragment caching by default, and to add page and action caching, you'll need to add `actionpack-page_caching` and `actionpack-action_caching` gems to your Gemfile. Rails with fetch the views, pages or actions from the cache store as opposed to makiing a request to the server, reducing app latency significantly and improving performance and scalability.

- **Memoizing expensive computations**.Memoization is a technique used in Ruby to speed up accessor methods by changing the results of methods. For example:

```ruby
def current_user
    @current_user ||= User.find(user_id)
end
```

Using the `||=` memoization pattern, you cache the database query result of the `@current_user` after the first time the method is invoked. All the subsequent calls reuse the value stored in the `@current_user` instance variable. The `||=` means that if the `@current user` instance variable isn't empty or null, don't evaluate the right-hand side of the expression and return its value, else evaluate the expression on the right. This improves performance by caching expensive method calls.

### Remove unused Gems

Each Rails gem consumes some memory during startup causing memory bloat and slowing down your app You should occasionally check how much memory gems use using the derailed benchmarks gem. Add `gem 'derailed_benchmarks', group: :development` to your Gemfile, then run `bundle exec derailed bundle:mem` and from the output identify gems consuming excessive memory and consider replacing them with lightweight alternatives.
![Terminal output showing the gems consuming the most memory in an app](gems.png)
From the screenshot above, you can see that `papertrail` consumes the most memory on startup out of all the gems, you then look for alternatives to replace the gem with a lightweight gem.

### Use CDN to reduce latency

A Content Delivery Network(CDN) refers to a geographically distributed group of servers that caches app data closer to the users. CDNs solve the latency (time between when an app makes a request for data and when the data from the server is rendered to the end-user) problem through the following ways:

1. They reduce app load time by reducing the distance between the end users by letting the users connect to the closest server geographically to them.
2. CDNs also offer the load balancing feature that evenly distributes the oncoming app traffic amongst multiple backend servers which prevents one server from being overloaded with requests hence improving app performance.

## Conclusion

Optimizing your Ruby on Rails app is crucial for keeping users engaged and your business growing. By implementing techniques like lazy loading, optimizing database queries, using memory profiling tools, caching data, removing unused gems, and leveraging CDNs, you can ensure your app runs smoothly and efficiently. Don't forget to monitor and fine-tune your app regularly to maintain peak performance. Start optimizing today to provide the best experience for your users and unlock your app's full potential.