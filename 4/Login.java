
public class Login extends HttpServlet {
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) {
      String url = request.getParameter("url");
      //only relative urls are allowed!
      if (url.startsWith("/")) {
        response.sendRedirect(url);
      }
    }
  }