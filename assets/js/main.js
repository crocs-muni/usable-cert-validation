// Collapse error details at page load
$(document).ready(function(){
    $('.collapse.show')
        .removeClass('show')
        .siblings('.card-header')
        .addClass('collapsed');
});

// Show navbar if necessary at page load and after scroll
function showNavbar() {
    var scrolled = $(this).scrollTop();
    if($(".navbar").offset().top > 50) {
        $(".navbar").addClass('navbar-scrolled');
    } else {
        $(".navbar").removeClass('navbar-scrolled');
    }
};
$(window).scroll(showNavbar);
$(document).ready(showNavbar);

// Open feedback tab after click
$(function() {
	$("#feedback .btn-secondary").click(function() {
        var feedback_box = $("#feedback .btn-secondary").siblings('.card');
        if (feedback_box.hasClass('collapsed')) {
            feedback_box.removeClass('collapsed');
        } else {
            feedback_box.addClass('collapsed');
        }
	});
});

// Drop justShown class after a delay
$(function() {
	$(".collapsed").click(function() {
        $(".justShown").removeClass('justShown');
        $(this).addClass('justShown');
	});
});
