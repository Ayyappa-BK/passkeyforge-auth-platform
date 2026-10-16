package dev.passkeyforge;
import jakarta.servlet.http.*;
import java.time.*;
import java.util.*;
import org.springframework.stereotype.Component;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.FindByIndexNameSessionRepository;
@Component
public class Sessions {
 final JdbcTemplate db;
 public Sessions(JdbcTemplate db) { this.db=db; }
 public String binding(HttpServletRequest req) {
  var s=req.getSession(); String b=(String)s.getAttribute("binding");
  if(b==null) { b=Crypto.token(); s.setAttribute("binding",b); } return b;
 }
 public void establish(HttpServletRequest req,UUID user,String level) {
  var old=req.getSession(false); if(old!=null) old.invalidate();
  var s=req.getSession(true); s.setAttribute("uid",user.toString()); s.setAttribute("level",level);
  s.setAttribute("issued",Instant.now().getEpochSecond()); s.setAttribute("verified",Instant.now().getEpochSecond());
  s.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,user.toString());
 }
 public void refresh(HttpServletRequest req,UUID user) {
  long verified=(Long)req.getSession().getAttribute("verified");
  long issued=(Long)req.getSession().getAttribute("issued");
  establish(req,user,"FULL");
  req.getSession().setAttribute("verified",verified);
  req.getSession().setAttribute("issued",issued);
 }
 public UUID require(HttpServletRequest req,String... levels) {
  var s=req.getSession(false); if(s==null) throw ApiError.denied();
  var issued=(Long)s.getAttribute("issued"); String level=(String)s.getAttribute("level");
  long max="FULL".equals(level)?28800:300;
  if(issued==null || Instant.now().getEpochSecond()-issued>max || !Arrays.asList(levels).contains(level)) throw ApiError.denied();
  return UUID.fromString((String)s.getAttribute("uid"));
 }
 public UUID recent(HttpServletRequest req) {
  UUID id=require(req,"FULL");
  if(Instant.now().getEpochSecond()-(Long)req.getSession().getAttribute("verified")>300)
   throw new ApiError(403,"Sign in again before changing security settings");
  return id;
 }
 public void revoke(UUID id) { db.update("delete from spring_session where principal_name=?",id.toString()); }
}
