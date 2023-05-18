package com.finalproject.mvc.sobeit.service;

import com.finalproject.mvc.sobeit.dto.ArticleResponseDTO;
import com.finalproject.mvc.sobeit.entity.*;
import com.finalproject.mvc.sobeit.repository.ArticleLikeRepo;
import com.finalproject.mvc.sobeit.repository.ArticleRepo;
import com.finalproject.mvc.sobeit.repository.ReplyRepo;
import com.finalproject.mvc.sobeit.repository.VoteRepo;
import lombok.RequiredArgsConstructor;
import org.json.simple.JSONObject;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleServiceImpl implements ArticleService{

    private final ArticleRepo articleRepo;
    private final ArticleLikeRepo articleLikeRepo;
    private final VoteRepo voteRepo;
    private final ReplyRepo replyRepo;

    /**
     * 글 작성
     * @param article
     */
    public Article writeArticle(Article article) {
        return articleRepo.save(article);
    }

    /**
     * 글 수정
     * @param userSeq
     * @param article
     * @return
     */
    public Article updateArticle(Long userSeq, Article article) {
        Article existingArticle = articleRepo.findById(article.getArticleSeq()).orElse(null); // 기존 작성글 가져오기
        if (existingArticle==null) { // 수정할 글이 없는 경우 예외 발생
            throw new RuntimeException("수정할 글이 없습니다.");
        }
        if (userSeq != existingArticle.getUser().getUserSeq()){ // 기존 글의 작성자가 아니면 예외 발생
            throw new RuntimeException("글의 작성자가 아닙니다.");
        }

        article.setWrittenDate(existingArticle.getWrittenDate()); // 작성시간 복사
        article.setArticleType(existingArticle.getArticleType()); // 타입 복사
        article.setEditedDate(LocalDateTime.now()); // 수정시간 등록
        return articleRepo.save(article);
    }

    /**
     * 글 삭제
     * @param userSeq
     * @param articleSeq
     */
    public void deleteArticle(Long userSeq, Long articleSeq) {
        Article foundArticle = articleRepo.findById(articleSeq).orElse(null);
        if (foundArticle==null){ // 삭제할 글이 없는 경우
            throw new RuntimeException("삭제할 글이 없습니다.");
        }

        if (userSeq!=foundArticle.getUser().getUserSeq()){ // 삭제 요청 유저가 작성자가 아닐 경우 예외 발생
            throw new RuntimeException("작성자가 아닙니다.");
        }
        articleRepo.deleteById(articleSeq);
    }
    //////////////////////////////////////////////////////////////////

    /**
     * 디테일 페이지
     * @param articleSeq
     * @return
     */
    @Override
    public ArticleResponseDTO articleDetail(Users user, Long articleSeq) {
        // 보려는 글 가져오기
        Article article = selectArticleById(articleSeq);

        if (article == null){ // 글이 없는 경우 예외 발생
            throw new RuntimeException("글이 존재하지 않습니다.");
        }
        // 글에 대한 권한 확인
        //if (article.getStatus()==2 && !맞팔체크){
        //    throw new RuntimeException("맞팔로우의 유저만 확인 가능한 글입니다.");
        //}
        //else
        if(article.getStatus()==3 && user.getUserId() != article.getUser().getUserId()){
            throw new RuntimeException("비공개 글입니다.");
        }

        // 댓글 수 가져오기
        int replyCnt = 0;

        // 좋아요 수 가져오기
        int likeCnt = 0;

        // 좋아요 여부 가져오기
        boolean isLiked = false;

        // 투표율 가져오기
        int [] voteRate = null;

        // 투표여부 가져오기
        boolean isVoted = false;

        // ArticleResponseDTO 반환
        ArticleResponseDTO articleResponseDTO = ArticleResponseDTO.builder()
                .user(user)
                .status(article.getStatus())
                .imageUrl(article.getImageUrl())
                .expenditureCategory(article.getExpenditureCategory())
                .amount(article.getAmount())
                .articleType(article.getArticleType())
                .consumptionDate(article.getConsumptionDate())
                .writtenDate(article.getWrittenDate())
                .isAllowed(article.getIsAllowed())
                .commentCnt(replyCnt)
                .likeCnt(likeCnt)
                .isLiked(isLiked)
                .isVoted(isVoted)
                .agree(voteRate[0]) // 찬성표수
                .disagree(voteRate[1]) // 반대표수
                .agreeRate(voteRate[2]) // 찬성표율
                .disagreeRate(voteRate[3]) // 반대표율
                .build();

        return articleResponseDTO;
    }

    /**
     * 아이디로 글 조회
     * @param articleSeq
     * @return 해당 번호 글
     */
    @Override
    public Article selectArticleById(Long articleSeq) {
        return articleRepo.findById(articleSeq).orElse(null);
    }

    /**
     * 글 하나에 대한 ArticleResponseDTO 가져오기
     * @param articleSeq
     * @return
     */
    @Override
    public ArticleResponseDTO findArticleResponse(Long articleSeq) {
        return null;
    }

    /**
     * 피드
     * @param user
     * @return
     */
    @Override
    public List<ArticleResponseDTO> feed(Users user){
        // 권한에 맞는 글번호 리스트 가져오기
        // ArticleResponseDTO 가져오기
        return null;
    }

    /**
     * 피드 글 번호 조회
     * @param userSeq
     * @return 유저가 볼 수 있는 권한의 글번호 리스트 최신순
     */
    @Override
    public List<Long> selectFeedArticleSeq(Long userSeq) {
        //
        return null;
    }
    //////////////////////////////////////////////////////////////////
    /**
     * 글 좋아요
     * @param articleLike
     */
    public boolean likeArticle(ArticleLike articleLike){
        boolean isLiked = false;
        ArticleLike existingLike = articleLikeRepo.findById(articleLike.getLikeSeq()).orElse(null); // 기존 좋아요가 있는 지 확인
        if (existingLike==null){ // 좋아요한 적 없으면 좋아요 생성
            articleLikeRepo.save(articleLike);
            isLiked = true;
        }
        else { // 좋아요한 적 있으면 좋아요 취소(삭제)
            articleLikeRepo.delete(existingLike);
        }
        return isLiked;
    }

    /**
     * 글 좋아요 여부 확인
     * @param userSeq
     * @param articleSeq
     * @return true : 이미 좋아요 함, false : 좋아요 안 함
     */
    @Override
    public boolean isArticleLike(Long userSeq, Long articleSeq) {
        ArticleLike articleLike = articleLikeRepo.findArticleLikeByUserSeqAndArticleSeq(userSeq, articleSeq).orElse(null);
        if (articleLike == null) return false;
        return true;
    }

    /**
     * 글 좋아요 수 확인
     */
    @Override
    public int countArticleLike(Long articleSeq){
        return articleLikeRepo.findCountArticleLikeByArticleSeq(articleSeq);
    }

    /**
     * 투표하기
     * @param vote
     * @return 생성된 투표
     */
    public Vote voteArticle(Vote vote){
        Vote votedVote = voteRepo.save(vote);
        return votedVote;
    }

    /**
     * 해당 사용자의 해당 글에 대한 투표 여부 확인
     * @param userSeq
     * @param articleSeq
     * @return true면 투표한 적 있음 / false면 투표한 적 없음
     */
    public boolean voteCheck(Long userSeq, Long articleSeq){
        Vote existingVote = voteRepo.findVoteByUserSeqAndArticleSeq(userSeq, articleSeq).orElse(null);
        if (existingVote==null) return false;
        return true;
    }

    /**
     * 투표수 확인
     * @param articleSeq
     * @return v[0] 찬성표수, v[1] 반대표수
     */
    public int[] voteCount(Long articleSeq){
        int[] voteValue = new int[2];
        voteValue[0] = voteRepo.findAgreeCountByArticleSeq(articleSeq);
        voteValue[1] = voteRepo.findDisagreeCountByArticleSeq(articleSeq);
        return voteValue;
    }

    /**
     * 투표율 확인
     * @param articleSeq
     * @return {"agree": 찬성표수, "disagree": 반대표수, "agreeRate: 찬성표율, "disagreeRate": 반대표율}
     */
    public JSONObject voteRate(Long articleSeq){
        int[] voteValue = voteCount(articleSeq);
        JSONObject rate = new JSONObject();
        rate.put("agree",voteValue[0]);
        rate.put("disagree",voteValue[1]);
        int agreeRate = 0;
        int disagreeRate = 0;
        if (voteValue[0]!=0 || voteValue[1]!=0) { // 투표수가 0이 아니라면
            agreeRate = voteValue[0]/(voteValue[0]+voteValue[1]) * 100;
            disagreeRate = 100 - agreeRate;
        }
        rate.put("agreeRate", agreeRate);
        rate.put("disagreeRate", disagreeRate);
        return rate;
    }


}
