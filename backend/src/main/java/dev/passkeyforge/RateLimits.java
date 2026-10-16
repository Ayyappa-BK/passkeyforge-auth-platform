package dev.passkeyforge;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;
@Service
public class RateLimits {
 final JdbcTemplate db;
 public RateLimits(JdbcTemplate db) { this.db=db; }
 public void check(String subject,int limit,int seconds) {
  long window=Math.floorDiv(System.currentTimeMillis()/1000,seconds);
  String key=Crypto.digest(subject+":"+window);
  Integer hits=db.queryForObject("insert into rate_buckets values(?,1,now()+make_interval(secs=>?)) on conflict(key) do update set hits=rate_buckets.hits+1 returning hits",Integer.class,key,seconds);
  if(hits!=null && hits>limit) throw new ApiError(429,"Too many attempts; retry after the rate window");
 }
}
