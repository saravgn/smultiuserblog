# Author: Sara Vagnarelli
# Multi User blog

Checkout the [live](http://smultiuserblog.appspot.com/) version of this project.


## Description
-----------------------------------

A logged User should be able to create an account with login/logout functionality, and create/edit/delete/like posts and comments.

## How to Run Project
------------------

* Install the [Google App Engine SDK for Python](https://cloud.google.com/appengine/downloads)
* Sign up for a GAE account ([instructions](https://sites.google.com/site/gdevelopercodelabs/app-engine/creating-your-app-engine-account))
* Clone the repo with ```https://github.com/saravgn/smultiuserblog.git```
* ```cd FSND-Blog-P3``` into the blog directory

run the application through the GAE Launcher GUI
- File -> Add Existing Application
- Add project
- Click Browse


### Project specifications
-----------------------------------

Blog must include the following features:
- Front page that lists blog posts.
- A form to submit new entries.
- Blog posts have their own page.

Registration must include the following features:
- A registration form that validates user input, and displays the error(s) when necessary.
- After a successful registration, a user is directed to a welcome page with a greeting, “Welcome, *name*” where *name* is a name set in a cookie.
- If a user attempts to visit a restricted page without being signed in (without having a cookie), then redirect to the Signup page.

Login must include the following features:
- Have a login form that validates user input, and displays the error(s) when necessary.

Users must include the following features:
- Users should only be able to edit/delete their posts. They receive an error message if they disobey this rule.
- Users can like posts, but not their own. They receive an error message if they disobey this rule.
- Users can comment on posts. They can only edit/delete their own posts, and they should receive an error message if they disobey this rule.

Code must conform to the [Python Style Guide](https://www.python.org/dev/peps/pep-0008/)