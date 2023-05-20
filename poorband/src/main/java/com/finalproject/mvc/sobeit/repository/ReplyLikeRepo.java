package com.finalproject.mvc.sobeit.repository;

import com.finalproject.mvc.sobeit.entity.Reply;
import com.finalproject.mvc.sobeit.entity.ReplyLike;
import com.finalproject.mvc.sobeit.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface ReplyLikeRepo extends JpaRepository<ReplyLike, Long> {
    ReplyLike findByReplyAndUser(Reply reply, Users user);

    @Query("select count(*) from ReplyLike r where r.reply.replySeq = ?1")
    int findCountReplyLikeByReplySeq(Long replySeq);
}
