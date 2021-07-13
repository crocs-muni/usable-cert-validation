// Page load routines
$(document).ready(function(){

    // Collapse error details at page load
    $('.collapse.show')
        .removeClass('show')
        .siblings('.card-header')
        .addClass('collapsed');

    // if intro is included
    if (document.getElementById("intro-fadeout")) {
        // show the intro button
        $('#intro-button').addClass('show');
        // show the gradient text-blocker (implicitly hidden for non JS users)
        document.getElementById("intro-fadeout").hidden = false;
    }

    // show error if the url redirects to it
    currentHref = window.location.href
    if (currentHref.includes('#') && currentHref.endsWith('-link')) {
        error = window.location.href.split('#')[1];
        error = error.substring(0, error.length - 5);
        $('#' + error).collapse('show');
    };
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

// on button click reveal the fadeout text
function hideIntroFadeout() {
    var id = setInterval(lowerOpacity, 20);
    var opacity = 1;

    function lowerOpacity() {
        if (opacity < 0) {
            clearInterval(id);
            document.getElementById("intro-fadeout").hidden = true;
        } else {
            opacity -= 0.05;
            document.getElementById('intro-fadeout').style.opacity = opacity;
        }
    }
}
