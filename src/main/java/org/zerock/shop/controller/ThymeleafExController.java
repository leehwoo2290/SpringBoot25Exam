package org.zerock.shop.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import org.zerock.shop.dto.ItemDto;
import java.time.LocalDateTime;

import java.util.ArrayList;
import java.util.List;

@Controller                                 // 컨트롤러 역할
@RequestMapping(value="/thymeleaf")      // http://localhost/thymeleaf
public class ThymeleafExController {

    @GetMapping(value = "/ex01") // http://localhost/thymeleaf/ex01 호출 시
    public String thymeleafExample01(Model model){ // Model 객체를 이용해서 데이터를 전이
        model.addAttribute("data", "타임리프 예제 입니다."); // Model객체에 값 추가 k:data , v: 타임리프 예제 입니다.
        return "thymeleafEx/thymeleafEx01";  // 리턴 thymeleafEx/thymeleafEx01.html
    }

    @GetMapping(value = "/ex02")  // http://localhost/thymeleaf/ex02 호출 시
    public String thymeleafExample02(Model model){ // Model 객체를 이용해서 데이터를 전이
        ItemDto itemDto = new ItemDto();            // ItemDto객체 생성
        itemDto.setItemDetail("상품 상세 설명");
        itemDto.setItemNm("테스트 상품1");
        itemDto.setPrice(10000);
        itemDto.setRegTime(LocalDateTime.now());

        model.addAttribute("itemDto", itemDto);  // Model영역에 k : itemDto, v : itemDto객체 전이
        return "thymeleafEx/thymeleafEx02";
    }

    @GetMapping(value = "/ex03")
    public String thymeleafExample03(Model model){

        List<ItemDto> itemDtoList = new ArrayList<>();  // 리스트 객체 생성

        for(int i=1;i<=10;i++){

            ItemDto itemDto = new ItemDto();
            itemDto.setItemDetail("상품 상세 설명"+i);
            itemDto.setItemNm("테스트 상품" + i);
            itemDto.setPrice(1000*i);
            itemDto.setRegTime(LocalDateTime.now());

            itemDtoList.add(itemDto);
        }

        model.addAttribute("itemDtoList", itemDtoList);  // Model영역에 k : itemDtoList, v : itemDto 리스트 객체 전이
        return "thymeleafEx/thymeleafEx03";
    }

    @GetMapping(value = "/ex04")
    public String thymeleafExample04(Model model){

        List<ItemDto> itemDtoList = new ArrayList<>();

        for(int i=1;i<=10;i++){

            ItemDto itemDto = new ItemDto();
            itemDto.setItemDetail("상품 상세 설명"+i);
            itemDto.setItemNm("테스트 상품" + i);
            itemDto.setPrice(1000*i);
            itemDto.setRegTime(LocalDateTime.now());

            itemDtoList.add(itemDto);
        }

        model.addAttribute("itemDtoList", itemDtoList);
        return "thymeleafEx/thymeleafEx04";
    }

    @GetMapping(value = "/ex05")
    public String thymeleafExample05(){
        return "thymeleafEx/thymeleafEx05";
    }

    @GetMapping(value = "/ex06")  // ex06?param1=kkk&param2=eee
    public String thymeleafExample06(String param1, String param2, Model model){
        model.addAttribute("param1", param1);  // url로 받는 param1 을 Model 영역에 저장
        model.addAttribute("param2", param2);  // url로 받는 param2 을 Model 영역에 저장
        return "thymeleafEx/thymeleafEx06";
    }

    @GetMapping(value = "/ex07")
    public String thymeleafExample07(){
        return "thymeleafEx/thymeleafEx07";
    }

}