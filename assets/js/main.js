$(document).ready(function(){
    // Collapse error details.
    $('.collapse.show')
        .removeClass('show')
        .siblings('.card-header')
        .addClass('collapsed');
});
// Show navbar if necessaryAdd shadow under navbar if the page is scrolled already on load.
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
